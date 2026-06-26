#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import process from "node:process";

const [output, stepsFile = ""] = process.argv.slice(2);
if (!output) {
  console.error("usage: write-fingerprint.mjs <output.json> [steps.tsv]");
  process.exit(2);
}

const doc = {
  schema_version: 1,
  generated_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
  setup_class: process.env.LOCKET_REFERENCE_RUNNER_CLASS ?? "unknown",
  setup_script: process.env.LOCKET_REFERENCE_RUNNER_SCRIPT ?? "unknown",
  apply_mode: (process.env.LOCKET_REFERENCE_RUNNER_APPLY ?? "0") === "1" ? "apply" : "dry-run",
  repository: {
    root: commandOutput("git", ["rev-parse", "--show-toplevel"]),
    commit_sha: commandOutput("git", ["rev-parse", "HEAD"]),
    branch: commandOutput("git", ["branch", "--show-current"]),
  },
  host: {
    os: firstLine(commandOutput("uname", ["-srmo"])),
    kernel: commandOutput("uname", ["-r"]),
    arch: commandOutput("uname", ["-m"]),
    cpu_model: firstLine(commandOutput("sh", ["-c", "sysctl -n machdep.cpu.brand_string 2>/dev/null || awk -F: '/model name/ { sub(/^ /, \"\", $2); print $2; exit }' /proc/cpuinfo 2>/dev/null"])),
    memory_bytes: firstLine(commandOutput("sh", ["-c", "sysctl -n hw.memsize 2>/dev/null || awk '/MemTotal/ { print $2 * 1024; exit }' /proc/meminfo 2>/dev/null"])),
    filesystem_type: firstLine(commandOutput("sh", ["-c", "df -T . 2>/dev/null | awk 'NR == 2 { print $2 }' || stat -f %T . 2>/dev/null"])),
    power_state: firstLine(commandOutput("sh", ["-c", "pmset -g batt 2>/dev/null | head -n 1 || true"])),
    thermal_state: commandOutput("sh", ["-c", "pmset -g therm 2>/dev/null || true"]),
    cpu_governor: firstLine(commandOutput("sh", ["-c", "cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || true"])),
    os_release: await fileText("/etc/os-release"),
  },
  tools: {
    rustc: commandOutput("rustc", ["-V"]),
    cargo: commandOutput("cargo", ["-V"]),
    git: commandOutput("git", ["--version"]),
  },
  applied_state: await steps(stepsFile),
};

await writeFile(output, `${stableStringify(doc, 0)}\n`);

function commandOutput(command, args) {
  try {
    const output = execFileSync(command, args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    return output.length > 0 ? output : "unknown";
  } catch {
    return "unknown";
  }
}

function firstLine(value) {
  const line = String(value ?? "").replace(/\r?\n[\s\S]*$/, "");
  return line.length > 0 ? line : "unknown";
}

async function fileText(path) {
  try {
    const text = (await readFile(path, "utf8")).trim();
    return text.length > 0 ? text : "unknown";
  } catch {
    return "unknown";
  }
}

async function steps(path) {
  if (!path) return [];
  let text;
  try {
    text = await readFile(path, "utf8");
  } catch {
    return [];
  }
  return text.split(/\r?\n/).filter(Boolean).map((line) => {
    const [name = "unknown", status = "unknown", detail = ""] = line.split("\t", 3);
    return { name, status, detail };
  });
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
