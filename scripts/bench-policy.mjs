#!/usr/bin/env node
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import process from "node:process";

const args = parseArgs(process.argv.slice(2));
if (args.help) usage(0);

for (const required of ["current", "mode", "report"]) {
  if (!args[required]) die(`missing --${dash(required)}`);
}
if (args.mode !== "pr" && args.mode !== "release") die("--mode must be pr or release");

const current = JSON.parse(await readFile(args.current, "utf8"));
const baseline = args.baseline ? JSON.parse(await readFile(args.baseline, "utf8")) : undefined;
const acceptedNote = args.accepted_regression_note ?? "";
const baselineByName = new Map();

if (baseline) {
  for (const bench of benchmarks(baseline)) {
    if (bench.name != null && bench.p95_ms != null) baselineByName.set(bench.name, bench);
  }
}

const rows = [];
const failures = [];
const hardTolerance = args.mode === "pr" ? 1.10 : 1.00;

for (const bench of benchmarks(current)) {
  const name = stringValue(bench, "name");
  const p95Ms = numberValue(bench, "p95_ms");
  const budgetMs = numberValue(bench, "budget_ms");
  const allowedMs = budgetMs * hardTolerance;

  if (p95Ms <= allowedMs) {
    rows.push([name, "hard budget", "passed", `p95 ${p95Ms.toFixed(3)} ms <= ${allowedMs.toFixed(3)} ms`]);
  } else {
    const detail = `p95 ${p95Ms.toFixed(3)} ms > ${allowedMs.toFixed(3)} ms`;
    rows.push([name, "hard budget", "failed", detail]);
    failures.push(`${name} hard budget: ${detail}`);
  }

  if (!baselineByName.has(name)) continue;
  const baselineP95 = numberValue(baselineByName.get(name), "p95_ms");
  const regressionLimit = baselineP95 * 1.20;
  if (p95Ms <= regressionLimit) {
    rows.push([name, "tracked regression", "passed", `p95 ${p95Ms.toFixed(3)} ms <= baseline ${baselineP95.toFixed(3)} ms + 20%`]);
  } else if (acceptedNote.length > 0) {
    rows.push([name, "tracked regression", "accepted", `p95 ${p95Ms.toFixed(3)} ms > baseline ${baselineP95.toFixed(3)} ms + 20%; note recorded`]);
  } else {
    const detail = `p95 ${p95Ms.toFixed(3)} ms > baseline ${baselineP95.toFixed(3)} ms + 20%`;
    rows.push([name, "tracked regression", "failed", detail]);
    failures.push(`${name} tracked regression: ${detail}`);
  }
}

await writeReport(args.report, rows, failures, args.mode, acceptedNote);

if (failures.length > 0) {
  console.error(`benchmark policy failed; see ${args.report}`);
  for (const failure of failures) console.error(` - ${failure}`);
  process.exit(1);
}

console.log(`benchmark policy passed; see ${args.report}`);

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
  console.log(`usage: bench-policy.mjs --current <summary.json> --mode <pr|release> --report <path>
       [--baseline <summary.json>] [--accepted-regression-note <text>]`);
  process.exit(code);
}

function die(message) {
  console.error(message);
  process.exit(2);
}

function dash(value) {
  return value.replaceAll("_", "-");
}

function benchmarks(summary) {
  if (!isObject(summary)) throw new Error("summary must be an object");
  if (!Array.isArray(summary.benchmarks)) throw new Error("summary benchmarks must be an array");
  return summary.benchmarks;
}

function stringValue(object, key) {
  if (!isObject(object) || object[key] == null || typeof object[key] === "object") {
    throw new Error(`benchmark missing ${key}`);
  }
  return String(object[key]);
}

function numberValue(object, key) {
  const value = stringValue(object, key);
  if (!/^[0-9]+(?:\.[0-9]+)?$/.test(value)) throw new Error(`benchmark ${key} must be numeric`);
  return Number(value);
}

async function writeReport(path, rows, failures, mode, acceptedNote) {
  await mkdir(dirname(path), { recursive: true });
  const lines = [
    "# Benchmark Policy",
    "",
    `- mode: ${mode}`,
    `- hard_budget_tolerance: ${mode === "pr" ? "10%" : "0%"}`,
    "- tracked_regression_tolerance: 20%",
    `- accepted_regression_note: ${acceptedNote.length > 0 ? "present" : "absent"}`,
    `- result: ${failures.length > 0 ? "failed" : "passed"}`,
    "",
    "| Benchmark | Check | Status | Detail |",
    "| --- | --- | --- | --- |",
  ];
  for (const [name, check, status, detail] of rows) {
    lines.push(`| ${name} | ${check} | ${status} | ${markdownEscape(detail)} |`);
  }
  lines.push("");
  await writeFile(path, lines.join("\n"));
}

function isObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function markdownEscape(value) {
  return String(value ?? "").replaceAll("|", "\\|").replace(/\r?\n/g, " ");
}
