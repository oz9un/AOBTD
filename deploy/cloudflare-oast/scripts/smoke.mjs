import { createHmac, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";

const baseURL = process.env.AOBTD_OAST_BASE_URL || "https://oast.aobtd.com";
const apiToken = keychainValue("aobtd-oast-api-token");
const signingKey = keychainValue("aobtd-oast-signing-key");
const nonce = randomBytes(16).toString("hex");
const signature = createHmac("sha256", signingKey).update(nonce).digest("hex").slice(0, 32);
const token = `v1.${nonce}.${signature}`;

const health = await fetch(`${baseURL}/health`);
const healthBody = await health.json();
assert(health.ok && healthBody.ok === true, "health check failed");

const unauthorized = await fetch(`${baseURL}/api/v1/probes/${token}/events`);
assert(unauthorized.status === 401, "polling endpoint accepted an unauthenticated request");

const invalidProbe = await fetch(`${baseURL}/c/not-a-signed-token`);
assert(invalidProbe.status === 404, "collector accepted an invalid probe token");

const callback = await fetch(`${baseURL}/c/${token}?smoke=1`, {
  headers: { "user-agent": "aobtd-oast-smoke" },
});
const callbackBody = await callback.text();
assert(callback.ok && callbackBody.trim() === `AOBTD_OAST_PROOF:${token}`, "valid callback failed");

let event;
for (let attempt = 0; attempt < 10; attempt += 1) {
  const poll = await fetch(`${baseURL}/api/v1/probes/${token}/events`, {
    headers: { authorization: `Bearer ${apiToken}` },
  });
  assert(poll.ok, `authenticated polling failed with ${poll.status}`);
  const body = await poll.json();
  event = body.events?.find((candidate) => candidate.raw_query === "smoke=1");
  if (event) break;
  await new Promise((resolve) => setTimeout(resolve, 500));
}
assert(event, "callback was not persisted or returned by polling");

process.stdout.write(
  `Live OAST smoke test passed: health, auth rejection, signature rejection, callback persistence, and polling (${event.method}).\n`,
);

function keychainValue(service) {
  if (process.platform !== "darwin") {
    throw new Error("This smoke script currently loads secrets from macOS Keychain.");
  }
  const result = spawnSync(
    "security",
    ["find-generic-password", "-a", process.env.USER || "aobtd", "-s", service, "-w"],
    { encoding: "utf8" },
  );
  if (result.error) throw result.error;
  if (result.status !== 0 || !result.stdout.trim()) {
    throw new Error(`Missing Keychain value for ${service}.`);
  }
  return result.stdout.trim();
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
