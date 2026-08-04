import assert from "node:assert/strict";
import { test } from "node:test";
import worker, { testing } from "../src/index.js";

const SIGNING_KEY = "test-signing-key";
const API_TOKEN = "test-api-token";

async function probeToken(random = "0123456789abcdef0123456789abcdef") {
  const signature = await testing.hmacHex(SIGNING_KEY, random);
  return `v1.${random}.${signature.slice(0, 32)}`;
}

class MemoryDB {
  constructor() {
    this.rows = [];
  }

  prepare(sql) {
    return {
      bind: (...values) => ({
        run: async () => {
          if (/INSERT INTO callback_events/.test(sql)) {
            const [probe_token, received_at_ms, method, path, raw_query, source_ip, colo, headers_json] = values;
            this.rows.push({
              id: this.rows.length + 1,
              probe_token,
              received_at_ms,
              method,
              path,
              raw_query,
              source_ip,
              colo,
              headers_json,
            });
          } else if (/DELETE FROM callback_events/.test(sql)) {
            this.rows = this.rows.filter((row) => row.received_at_ms >= values[0]);
          }
          return { success: true };
        },
        all: async () => {
          const [token, after, limit] = values;
          return {
            results: this.rows
              .filter((row) => row.probe_token === token && row.received_at_ms >= after)
              .slice(0, limit),
          };
        },
      }),
    };
  }
}

function env(db = new MemoryDB()) {
  return {
    DB: db,
    AOBTD_OAST_SIGNING_KEY: SIGNING_KEY,
    AOBTD_OAST_API_TOKEN: API_TOKEN,
  };
}

const ctx = { waitUntil(promise) { void promise; } };

test("valid signed callback is stored and returned with an in-band marker", async () => {
  const db = new MemoryDB();
  const bindings = env(db);
  const token = await probeToken();
  const response = await worker.fetch(
    new Request(`https://oast.aobtd.com/c/${token}/image.png?source=test`, {
      headers: { "user-agent": "SSRF client", authorization: "must-not-be-stored" },
    }),
    bindings,
    ctx,
  );
  assert.equal(response.status, 200);
  assert.equal((await response.text()).trim(), `AOBTD_OAST_PROOF:${token}`);
  assert.equal(db.rows.length, 1);
  assert.equal(JSON.parse(db.rows[0].headers_json).authorization, undefined);
});

test("poll API requires bearer auth and returns the correlated event", async () => {
  const db = new MemoryDB();
  const bindings = env(db);
  const token = await probeToken();
  await worker.fetch(new Request(`https://oast.aobtd.com/c/${token}`), bindings, ctx);

  const denied = await worker.fetch(
    new Request(`https://oast.aobtd.com/api/v1/probes/${token}/events`),
    bindings,
    ctx,
  );
  assert.equal(denied.status, 401);

  const allowed = await worker.fetch(
    new Request(`https://oast.aobtd.com/api/v1/probes/${token}/events`, {
      headers: { authorization: `Bearer ${API_TOKEN}` },
    }),
    bindings,
    ctx,
  );
  assert.equal(allowed.status, 200);
  const body = await allowed.json();
  assert.equal(body.events.length, 1);
  assert.equal(body.events[0].path, `/c/${token}`);
});

test("unsigned callback tokens are rejected without storing data", async () => {
  const db = new MemoryDB();
  const response = await worker.fetch(
    new Request("https://oast.aobtd.com/c/v1.0123456789abcdef0123456789abcdef.00000000000000000000000000000000"),
    env(db),
    ctx,
  );
  assert.equal(response.status, 404);
  assert.equal(db.rows.length, 0);
});
