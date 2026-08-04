import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";

const secrets = [
  {
    workerName: "AOBTD_OAST_API_TOKEN",
    keychainService: "aobtd-oast-api-token",
  },
  {
    workerName: "AOBTD_OAST_SIGNING_KEY",
    keychainService: "aobtd-oast-signing-key",
  },
];

for (const item of secrets) {
  const value = randomBytes(32).toString("hex");
  runWithSecret("npx", ["wrangler", "secret", "put", item.workerName], value);
  if (process.platform === "darwin") {
    runWithInput(
      "security",
      [
        "add-generic-password",
        "-a",
        process.env.USER || "aobtd",
        "-s",
        item.keychainService,
        "-U",
        "-w",
      ],
      `${value}\n${value}\n`,
    );
  }
}

if (process.platform === "darwin") {
  process.stdout.write("Worker secrets rotated and matching values saved in macOS Keychain.\n");
} else {
  process.stdout.write(
    "Worker secrets rotated. Store matching scanner values in your operating-system secret manager before closing this process.\n",
  );
}

function runWithSecret(command, args, secret) {
  runWithInput(command, args, `${secret}\n`);
}

function runWithInput(command, args, input) {
  const result = spawnSync(command, args, {
    cwd: new URL("..", import.meta.url),
    input,
    encoding: "utf8",
    stdio: ["pipe", "inherit", "inherit"],
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed with status ${result.status}`);
  }
}
