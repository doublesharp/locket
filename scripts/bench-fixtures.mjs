#!/usr/bin/env node
import { createHash } from "node:crypto";
import { chmod, mkdir, rm, writeFile as fsWriteFile } from "node:fs/promises";
import process from "node:process";

const args = parseArgs(process.argv.slice(2));
if (args.help) usage(0);

const profile = args.profile ?? "smoke";
const out = args.out ?? "target/bench-fixtures";
if (!/^(?:smoke|pr|release)$/.test(profile)) die("--profile must be smoke, pr, or release");

process.umask(0o077);
await rm(out, { recursive: true, force: true });
await mkdir(out, { recursive: true, mode: 0o700 });

const sizes = profileSizes(profile);
await writeMetadataFixture(`${out}/metadata`);
await writeRuntimeFixture(`${out}/runtime`);
await writeReferenceFixture(`${out}/reference-resolution`);
await writeScanFixture(`${out}/staged-scan`, sizes.staged_scan_bytes);
await writeFullScanFixture(`${out}/full-scan`, sizes.full_scan_bytes);
await writeArgon2Fixture(`${out}/argon2`);
await writeManifest(`${out}/manifest.json`, profile, sizes);

console.log(`benchmark fixtures written to ${out} (${profile})`);

function parseArgs(argv) {
  const parsed = {};
  while (argv.length > 0) {
    const arg = argv.shift();
    if (arg === "--help") {
      parsed.help = true;
      continue;
    }
    const match = /^--([a-z0-9-]+)$/.exec(arg);
    if (!match) die(`unknown argument: ${arg}`);
    if (argv.length === 0) die(`missing value for ${arg}`);
    parsed[match[1].replaceAll("-", "_")] = argv.shift();
  }
  return parsed;
}

function usage(code) {
  console.log("usage: bench-fixtures.mjs [--profile smoke|pr|release] [--out <dir>]");
  process.exit(code);
}

function die(message) {
  console.error(message);
  process.exit(2);
}

function profileSizes(profile) {
  if (profile === "smoke") return { staged_scan_bytes: 96 * 1024, full_scan_bytes: 1 * 1024 * 1024 };
  if (profile === "pr") return { staged_scan_bytes: 2 * 1024 * 1024, full_scan_bytes: 250 * 1024 * 1024 };
  return { staged_scan_bytes: 2 * 1024 * 1024, full_scan_bytes: 1024 * 1024 * 1024 };
}

async function writeMetadataFixture(dir) {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const profiles = Array.from({ length: 3 }, (_, idx) => ({
    profile_id: sprintf("profile-%02d", idx + 1),
    name_alias: sprintf("profile-label-%02d", idx + 1),
  }));
  const secrets = [];
  for (let idx = 1; idx <= 150; idx++) {
    secrets.push({
      secret_id: sprintf("secret-%03d", idx),
      name_alias: sprintf("secret-label-%03d", idx),
      profile_id: profiles[(idx - 1) % profiles.length].profile_id,
      state: idx <= 50 ? "active" : "metadata-only",
      current_version: idx <= 50 ? 1 : null,
      value_materialized: false,
    });
  }
  const policies = Array.from({ length: 10 }, (_, offset) => {
    const idx = offset + 1;
    return {
      policy_id: sprintf("policy-%02d", idx),
      command_alias: sprintf("policy-command-%02d", idx),
      required_secret_aliases: Array.from({ length: 5 }, (_, inner) => sprintf("secret-label-%03d", idx + inner)),
    };
  });
  const trustedRoots = Array.from({ length: 5 }, (_, idx) => ({
    root_id: sprintf("trusted-root-%02d", idx + 1),
    path_alias: sprintf("root-label-%02d", idx + 1),
  }));
  const audit = Array.from({ length: 25 }, (_, offset) => {
    const idx = offset + 1;
    return {
      sequence: idx,
      action: idx === 1 ? "INIT" : "METADATA_FIXTURE",
      hmac_ok: true,
      prev_hmac_digest: sha256(`prev:${idx}`),
    };
  });
  await writeJson(`${dir}/project.json`, {
    fixture: "metadata",
    profiles,
    secrets,
    policies,
    trusted_roots: trustedRoots,
    audit_chain: audit,
  });
}

async function writeRuntimeFixture(dir) {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const secrets = [];
  for (let idx = 1; idx <= 50; idx++) {
    const bytes = 16 + ((idx * 83) % (4096 - 16));
    secrets.push({
      env_name: sprintf("SECRET_%03d", idx),
      value_bytes: bytes,
      value_seed_digest: sha256(`runtime-value-seed:${idx}:${bytes}`),
      plaintext_persisted: false,
    });
  }
  await writeJson(`${dir}/runtime.json`, {
    fixture: "runtime",
    active_secret_count: 50,
    policy_name: "runtime-all-secrets",
    secret_material: secrets,
    references: Array.from({ length: 10 }, (_, idx) => sprintf("lk://profile-label-01/SECRET_%03d", idx + 1)),
  });
}

async function writeReferenceFixture(dir) {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const states = ["current", "pinned_current", "deprecated_in_grace", "expired", "missing", "unauthorized"];
  const refs = [];
  for (let idx = 1; idx <= 500; idx++) {
    const state = states[(idx - 1) % states.length];
    const version = /pinned|deprecated|expired/.test(state) ? "@v2" : "";
    refs.push({
      uri: sprintf("lk://profile-label-%02d/SECRET_%03d%s", ((idx - 1) % 3) + 1, idx, version),
      expected_state: state,
      value_seed_digest: /missing|unauthorized/.test(state) ? null : sha256(`reference-value-seed:${idx}`),
    });
  }
  await writeJson(`${dir}/references.json`, { fixture: "reference-resolution", references: refs });
}

async function writeScanFixture(dir, targetBytes) {
  await mkdir(`${dir}/repo/src`, { recursive: true, mode: 0o700 });
  await mkdir(`${dir}/repo/.env.d`, { recursive: true, mode: 0o700 });
  let bytes = 0;
  bytes += await writeSizedFile(`${dir}/repo/src/app.txt`, targetBytes / 2, "provider-shaped-token AKIAIOSFODNN7EXAMPLE\n");
  bytes += await writeSizedFile(`${dir}/repo/.env.d/local.env`, targetBytes / 4, "PUBLIC_PLACEHOLDER=fixture\n");
  bytes += await writeSizedFile(`${dir}/repo/src/high-entropy.txt`, targetBytes - bytes, "Zml4dHVyZS1oaWdoLWVudHJvcHktbm90LWEtc2VjcmV0\n");
  await writeJson(`${dir}/manifest.json`, {
    fixture: "staged-scan",
    bytes,
    notes: "Synthetic invalid tokens and deterministic high-entropy-looking text only.",
  });
}

async function writeFullScanFixture(dir, targetBytes) {
  await mkdir(`${dir}/repo/src/nested`, { recursive: true, mode: 0o700 });
  await mkdir(`${dir}/repo/ignored`, { recursive: true, mode: 0o700 });
  await mkdir(`${dir}/repo/bin`, { recursive: true, mode: 0o700 });
  await writeFile(`${dir}/repo/.gitignore`, "ignored/\n");
  let remaining = targetBytes;
  const files = [
    [`${dir}/repo/src/nested/generated-a.txt`, "text", Math.trunc(targetBytes * 0.30)],
    [`${dir}/repo/src/nested/generated-b.txt`, "text", Math.trunc(targetBytes * 0.25)],
    [`${dir}/repo/ignored/build.log`, "ignored", Math.trunc(targetBytes * 0.15)],
    [`${dir}/repo/bin/blob.bin`, "binary", Math.trunc(targetBytes * 0.20)],
  ];
  let written = 0;
  for (const [path, kind, bytes] of files) {
    written += await writeSizedFile(path, bytes, `${kind} fixture line ${sha256(path)}\n`);
    remaining -= bytes;
  }
  if (remaining > 0) written += await writeSizedFile(`${dir}/repo/src/remainder.txt`, remaining, "remainder fixture line\n");
  await writeJson(`${dir}/manifest.json`, {
    fixture: "full-scan",
    requested_bytes: targetBytes,
    written_bytes: written,
    includes_ignored_paths: true,
    includes_binary_paths: true,
  });
}

async function writeArgon2Fixture(dir) {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await writeJson(`${dir}/argon2.json`, {
    fixture: "argon2",
    passphrase_fallback: {
      kdf: "argon2id",
      memory_kib: 65536,
      iterations: 3,
      parallelism: 1,
      test_passphrase_seed_digest: sha256("argon2-passphrase-fixture"),
      test_salt_digest: sha256("argon2-passphrase-salt"),
      plaintext_persisted: false,
    },
    recovery_envelope: {
      kdf: "argon2id",
      memory_kib: 262144,
      iterations: 4,
      parallelism: 1,
      test_recovery_code_seed_digest: sha256("argon2-recovery-fixture"),
      test_salt_digest: sha256("argon2-recovery-salt"),
      plaintext_persisted: false,
    },
  });
}

async function writeManifest(path, profile, sizes) {
  await writeJson(path, {
    schema: "locket-bench-fixtures-v1",
    profile,
    generated_content: "deterministic synthetic metadata and corpora",
    plaintext_secrets_persisted: false,
    staged_scan_bytes: sizes.staged_scan_bytes,
    full_scan_bytes: sizes.full_scan_bytes,
    fixtures: ["metadata", "runtime", "reference-resolution", "staged-scan", "full-scan", "argon2"],
  });
}

async function writeSizedFile(path, targetBytes, seed) {
  targetBytes = Math.trunc(targetBytes);
  let written = 0;
  let counter = 0;
  const chunks = [];
  while (written < targetBytes) {
    const line = `${String(counter).padStart(8, "0")} ${seed} ${sha256(`${path}:${counter}`)}\n`;
    const remaining = targetBytes - written;
    if (line.length > remaining) {
      chunks.push(line.slice(0, remaining));
      written += remaining;
      break;
    }
    chunks.push(line);
    written += line.length;
    counter++;
  }
  await writeFile(path, chunks.join(""));
  return written;
}

async function writeJson(path, value) {
  await writeFile(path, `${stableStringify(value, 0)}\n`);
}

async function writeFile(path, content) {
  await fsWriteFile(path, content);
  await chmod(path, 0o600);
}

function stableStringify(value, depth) {
  const indent = "   ".repeat(depth);
  const nextIndent = "   ".repeat(depth + 1);
  if (value === null) return "null";
  if (typeof value === "boolean" || typeof value === "number") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    if (value.length === 0) return "[]";
    return `[\n${value.map((item) => `${nextIndent}${stableStringify(item, depth + 1)}`).join(",\n")}\n${indent}]`;
  }
  const keys = Object.keys(value).sort();
  if (keys.length === 0) return "{}";
  return `{\n${keys.map((key) => `${nextIndent}${JSON.stringify(key)} : ${stableStringify(value[key], depth + 1)}`).join(",\n")}\n${indent}}`;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function sprintf(format, ...values) {
  let index = 0;
  return format.replace(/%0?(\d*)d|%s/g, (match, width) => {
    const value = values[index++];
    if (match.endsWith("d")) return String(Number(value)).padStart(Number(width || 0), "0");
    return String(value);
  });
}
