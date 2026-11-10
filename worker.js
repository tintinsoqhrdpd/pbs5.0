// Trigger Cloudflare deployment
const DEFAULT_HOUSEMATES = [
  { id: "1", name: "Florie", letter: "A" },
  { id: "2", name: "Karylle", letter: "B" },
  { id: "3", name: "Juna", letter: "C" },
  { id: "4", name: "Sophia", letter: "D" },
  { id: "5", name: "Reez", letter: "E" }
];

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" }
  });

const base64url = (bytes) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const fromBase64url = (value) => {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
};

async function signToken(payload, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const body = base64url(new TextEncoder().encode(JSON.stringify(payload)));
  const signature = await crypto.subtle.sign(
    "HMAC", key, new TextEncoder().encode(body)
  );
  return ${body}.${base64url(signature)};
}

async function verifyToken(token, secret) {
  try {
    const [body, signature] = token.split(".");
    if (!body || !signature) return false;

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      fromBase64url(signature),
      new TextEncoder().encode(body)
    );

    if (!valid) return false;

    const payload = JSON.parse(
      new TextDecoder().decode(fromBase64url(body))
    );

    return payload.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

async function isAdmin(request, env) {
  const authorization = request.headers.get("Authorization") || "";
  const token = authorization.startsWith("Bearer ")
    ? authorization.slice(7)
    : "";

  if (!token || !env.SESSION_SECRET) return false;
  return await verifyToken(token, env.SESSION_SECRET);
}

async function ensureDefaults(db) {
  for (const person of DEFAULT_HOUSEMATES) {
    await db.prepare(`
      INSERT OR IGNORE INTO eviction_housemates
      (id, name, letter, photo, active)
      VALUES (?, ?, ?, '', 1)
    `).bind(person.id, person.name, person.letter).run();
  }

  await db.prepare(`
    INSERT OR IGNORE INTO eviction_settings (id) VALUES (1)
  `).run();
}

async function getSettings(db) {
  return await db.prepare(`
    SELECT voting_start, voting_end, force_locked, tally_visible
    FROM eviction_settings WHERE id = 1
  `).first();
}

async function getState(db, admin) {
  const settings = await getSettings(db);

  const housemates = await db.prepare(`
    SELECT h.id, h.name, h.letter, h.photo,
      SUM(CASE WHEN v.vote_type = 'SAVE' THEN 1 ELSE 0 END) AS save_votes,
      SUM(CASE WHEN v.vote_type = 'EVICT' THEN 1 ELSE 0 END) AS evict_votes
    FROM eviction_housemates h
    LEFT JOIN eviction_votes v ON v.housemate_id = h.id
    WHERE h.active = 1
    GROUP BY h.id
    ORDER BY h.created_at ASC
  `).all();

  const now = Date.now();
  const start = settings?.voting_start
    ? new Date(settings.voting_start).getTime() : null;
  const end = settings?.voting_end
    ? new Date(settings.voting_end).getTime() : null;

  const timeLocked =
    (start !== null && now < start) ||
    (end !== null && now >= end);

  const locked = Boolean(settings?.force_locked) || timeLocked;

  return {
    housemates: (housemates.results || []).map(person => ({
      id: person.id,
      name: person.name,
      letter: person.letter,
      photo: person.photo || "",
      saveVotes: admin || settings?.tally_visible
        ? Number(person.save_votes || 0) : null,
      evictVotes: admin || settings?.tally_visible
        ? Number(person.evict_votes || 0) : null
    })),
    schedule: {
      startTime: settings?.voting_start || "",
      endTime: settings?.voting_end || "",
      forceLock: Boolean(settings?.force_locked),
      locked
    },
    tallyVisible: Boolean(settings?.tally_visible)
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (!path.startsWith("/api/")) {
        return env.ASSETS.fetch(request);
      }

      if (!env.DB) return json({ error: "Database binding is missing." }, 500);

      await ensureDefaults(env.DB);

      if (request.method === "GET" && path === "/api/state") {
        const admin = await isAdmin(request, env);
        return json(await getState(env.DB, admin));
      }

      if (request.method === "POST" && path === "/api/votes") {
        const body = await request.json();
        const housemateId = String(body.housemateId || "");
        const voteType = String(body.type || "").toUpperCase();

        if (!housemateId || !["SAVE", "EVICT"].includes(voteType)) {
          return json({ error: "Invalid vote." }, 400);
        }

        const settings = await getSettings(env.DB);
        const now = Date.now();
        const start = settings?.voting_start
          ? new Date(settings.voting_start).getTime() : null;
        const end = settings?.voting_end
          ? new Date(settings.voting_end).getTime() : null;

        if (settings?.force_locked ||
            (start !== null && now < start) ||
            (end !== null && now >= end)) {
          return json({ error: "Voting is currently closed." }, 403);
        }

        const person = await env.DB.prepare(`
          SELECT id FROM eviction_housemates
          WHERE id = ? AND active = 1
        `).bind(housemateId).first();

        if (!person) return json({ error: "Housemate not found." }, 404);

        await env.DB.prepare(`
          INSERT INTO eviction_votes (housemate_id, vote_type)
          VALUES (?, ?)
        `).bind(housemateId, voteType).run();

        return json({ success: true });
      }

      if (request.method === "POST" && path === "/api/admin/login") {
        const body = await request.json();

        if (!env.ADMIN_PASSCODE || !env.SESSION_SECRET) {
          return json({ error: "Admin secrets have not been configured." }, 500);
        }

        if (String(body.passcode || "") !== env.ADMIN_PASSCODE) {
          return json({ error: "Incorrect passcode." }, 401);
        }

        const token = await signToken({
          admin: true,
          exp: Math.floor(Date.now() / 1000) + 8 * 60 * 60
        }, env.SESSION_SECRET);

        return json({ success: true, token });
      }

      if (request.method === "POST" && path === "/api/admin/settings") {
        if (!await isAdmin(request, env)) {
          return json({ error: "Admin access required." }, 401);
        }

        const body = await request.json();

        await env.DB.prepare(`
          UPDATE eviction_settings
          SET voting_start = ?,
              voting_end = ?,
              force_locked = ?,
              tally_visible = ?
          WHERE id = 1
        `).bind(
          body.startTime || null,
          body.endTime || null,
          body.forceLock ? 1 : 0,
          body.tallyVisible ? 1 : 0
        ).run();

        return json({ success: true });
      }

      if (request.method === "POST" && path === "/api/admin/housemates") {
        if (!await isAdmin(request, env)) {
          return json({ error: "Admin access required." }, 401);
        }

        const body = await request.json();
        const name = String(body.name || "").trim();
        const letter = String(body.letter || "").trim();
        const photo = String(body.photo || "");

        if (!name) return json({ error: "Housemate name is required." }, 400);
        if (photo.length > 500000) {
          return json({ error: "Photo is too large. Please use an image URL." }, 400);
        }

        const id = crypto.randomUUID();

        await env.DB.prepare(`
          INSERT INTO eviction_housemates (id, name, letter, photo, active)
          VALUES (?, ?, ?, ?, 1)
        `).bind(id, name, letter, photo).run();

        return json({ success: true, id });
      }

      if (request.method === "DELETE" &&
          path.startsWith("/api/admin/housemates/")) {
        if (!await isAdmin(request, env)) {
          return json({ error: "Admin access required." }, 401);
        }

        const id = decodeURIComponent(path.split("/").pop());

        await env.DB.prepare(`
          UPDATE eviction_housemates SET active = 0 WHERE id = ?
        `).bind(id).run();

        return json({ success: true });
      }

      if (request.method === "POST" && path === "/api/admin/reset-votes") {
        if (!await isAdmin(request, env)) {
          return json({ error: "Admin access required." }, 401);
        }

        await env.DB.prepare(DELETE FROM eviction_votes).run();
        return json({ success: true });
      }

      return json({ error: "API route not found." }, 404);

    } catch (error) {
      return json({ error: "Server error.", details: error.message }, 500);
    }
  }
};
Compose
Write to Justin Aranas

