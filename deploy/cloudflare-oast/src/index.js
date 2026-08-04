const TOKEN_RE = /^v1\.([a-f0-9]{32})\.([a-f0-9]{32})$/;
const MAX_EVENTS_PER_POLL = 100;
const EVENT_RETENTION_MS = 24 * 60 * 60 * 1000;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return json({ ok: true, service: "aobtd-oast" });
    }

    const apiMatch = url.pathname.match(/^\/api\/v1\/probes\/([^/]+)\/events$/);
    if (apiMatch) {
      return pollEvents(request, env, decodeURIComponent(apiMatch[1]), url);
    }

    const callbackMatch = url.pathname.match(/^\/c\/([^/]+)(?:\/.*)?$/);
    if (callbackMatch) {
      return collectCallback(request, env, ctx, decodeURIComponent(callbackMatch[1]), url);
    }

    return json({ error: "not_found" }, 404);
  },
};

async function collectCallback(request, env, ctx, token, url) {
  if (!(await validProbeToken(token, env.AOBTD_OAST_SIGNING_KEY))) {
    return json({ error: "invalid_probe" }, 404);
  }

  const now = Date.now();
  const headers = selectedHeaders(request.headers);
  await env.DB.prepare(
    `INSERT INTO callback_events
       (probe_token, received_at_ms, method, path, raw_query, source_ip, colo, headers_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      token,
      now,
      request.method,
      url.pathname,
      url.search.slice(1),
      request.headers.get("cf-connecting-ip") || "",
      request.cf?.colo || "",
      JSON.stringify(headers),
    )
    .run();

  ctx.waitUntil(
    env.DB.prepare("DELETE FROM callback_events WHERE received_at_ms < ?")
      .bind(now - EVENT_RETENTION_MS)
      .run()
      .catch(() => undefined),
  );

  return new Response(`AOBTD_OAST_PROOF:${token}\n`, {
    status: 200,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

async function pollEvents(request, env, token, url) {
  if (request.method !== "GET") {
    return json({ error: "method_not_allowed" }, 405, { allow: "GET" });
  }
  if (!(await authorized(request, env.AOBTD_OAST_API_TOKEN))) {
    return json({ error: "unauthorized" }, 401, {
      "www-authenticate": 'Bearer realm="aobtd-oast"',
    });
  }
  if (!(await validProbeToken(token, env.AOBTD_OAST_SIGNING_KEY))) {
    return json({ error: "invalid_probe" }, 404);
  }

  const after = nonNegativeInteger(url.searchParams.get("after"));
  const result = await env.DB.prepare(
    `SELECT id, received_at_ms, method, path, raw_query, source_ip, colo, headers_json
       FROM callback_events
      WHERE probe_token = ? AND received_at_ms >= ?
      ORDER BY received_at_ms ASC, id ASC
      LIMIT ?`,
  )
    .bind(token, after, MAX_EVENTS_PER_POLL)
    .all();

  const events = (result.results || []).map((row) => ({
    id: Number(row.id),
    received_at_ms: Number(row.received_at_ms),
    method: String(row.method || ""),
    path: String(row.path || ""),
    raw_query: String(row.raw_query || ""),
    source_ip: String(row.source_ip || ""),
    colo: String(row.colo || ""),
    headers: safeJSON(row.headers_json),
  }));
  return json({ probe_token: token, events });
}

async function validProbeToken(token, signingKey) {
  const match = TOKEN_RE.exec(token || "");
  if (!match || !signingKey) return false;
  const expected = await hmacHex(signingKey, match[1]);
  return constantTimeEqual(expected.slice(0, 32), match[2]);
}

async function authorized(request, expectedToken) {
  if (!expectedToken) return false;
  const header = request.headers.get("authorization") || "";
  const prefix = "Bearer ";
  if (!header.startsWith(prefix)) return false;
  return constantTimeEqual(header.slice(prefix.length), expectedToken);
}

async function hmacHex(secret, value) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return [...new Uint8Array(signature)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function selectedHeaders(headers) {
  const allowed = ["accept", "content-type", "user-agent", "host", "cf-ray", "x-forwarded-proto"];
  const result = {};
  for (const name of allowed) {
    const value = headers.get(name);
    if (value) result[name] = value.slice(0, 1024);
  }
  return result;
}

function nonNegativeInteger(raw) {
  const value = Number.parseInt(raw || "0", 10);
  return Number.isFinite(value) && value >= 0 ? value : 0;
}

function safeJSON(raw) {
  try {
    const parsed = JSON.parse(String(raw || "{}"));
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function constantTimeEqual(a, b) {
  a = String(a || "");
  b = String(b || "");
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function json(value, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders,
    },
  });
}

export const testing = {
  hmacHex,
  validProbeToken,
  constantTimeEqual,
  selectedHeaders,
};
