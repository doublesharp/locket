#!/usr/bin/env node
import { readdir, readFile, stat } from "node:fs/promises";
import { join, posix } from "node:path";
import process from "node:process";

const requiredSpecs = [
  "index.md", "product.md", "invariants.md", "architecture.md", "data-model.md", "storage.md",
  "crypto.md", "project-cli.md", "policy.md", "runtime.md", "agent.md", "integrations.md",
  "scan-redaction.md", "desktop.md", "audit.md", "team-sync-recovery.md", "operations.md",
  "performance.md", "performance-reference-runner.md", "errors.md", "engineering.md", "testing.md", "fuzzing.md",
];
const requiredSpecSet = new Set(requiredSpecs);
const errors = [];

for (const spec of requiredSpecs) {
  if (!(await isFile(`docs/specs/${spec}`))) errors.push(`missing required spec: docs/specs/${spec}`);
}

for (const file of (await readdir("docs/specs")).filter((name) => name.endsWith(".md")).sort()) {
  if (!requiredSpecSet.has(file)) errors.push(`unregistered spec file: docs/specs/${file}`);
}

await checkSpecIndex();
await checkSpecBacklinks();
await checkMakeTargets();

const markdownFiles = ["README.md", ...(await walkMarkdown("docs"))].sort();
const anchorsByFile = new Map();

for (const file of markdownFiles) {
  const anchors = new Set();
  for (const line of (await readFile(file, "utf8")).split(/\n/)) {
    const match = /^(#{1,6})\s+(.+?)\s*#*\s*$/.exec(line);
    if (match) {
      const anchor = githubAnchor(match[2]);
      if (anchor) anchors.add(anchor);
    }
  }
  anchorsByFile.set(file, anchors);
}

for (const file of markdownFiles) {
  await checkMarkdownLint(file);
  const content = await readFile(file, "utf8");
  const lines = content.split(/(?<=\n)/);
  for (const [index, line] of lines.entries()) {
    const regex = /\[[^\]]+\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g;
    for (const match of line.matchAll(regex)) {
      const target = match[1];
      if (/^(?:https?|mailto):/.test(target)) continue;
      if (target.startsWith("#") && checkAnchor(file, target.slice(1), anchorsByFile)) continue;
      const [rawPath, anchor] = target.split("#", 2);
      const pathPart = uriDecode(rawPath);
      const linked = normalizePath(posix.join(dirname(file), pathPart));
      if (!linked || !(await isFile(linked))) {
        errors.push(`${file}:${index + 1} missing link target: ${target}`);
        continue;
      }
      if (anchor != null && !checkAnchor(linked, anchor, anchorsByFile)) {
        errors.push(`${file}:${index + 1} missing anchor '${anchor}' in ${linked}`);
      }
    }
  }
}

if (errors.length > 0) {
  console.error("docs-check failed:");
  for (const error of errors) console.error(` - ${error}`);
  process.exit(1);
}

console.log("docs-check passed");

async function checkSpecIndex() {
  const content = await readFile("docs/specs/index.md", "utf8");
  const readingOrder = [];
  let inReadingOrder = false;
  for (const line of content.split(/\n/)) {
    if (/^## Reading Order\s*$/.test(line)) {
      inReadingOrder = true;
      continue;
    }
    if (inReadingOrder && /^##\s+/.test(line)) break;
    if (!inReadingOrder) continue;
    const match = /^\s*-\s+\[[^\]]+\]\(([^)#]+)(?:#[^)]+)?\)\s*$/.exec(line);
    if (match) readingOrder.push(match[1]);
  }
  const expected = requiredSpecs.filter((spec) => spec !== "index.md");
  if (readingOrder.join("\n") !== expected.join("\n")) {
    errors.push(`docs/specs/index.md Reading Order must match required spec list: expected [${expected.join(" ")}], found [${readingOrder.join(" ")}]`);
  }
}

async function checkSpecBacklinks() {
  for (const spec of requiredSpecs) {
    if (spec === "index.md") continue;
    const path = `docs/specs/${spec}`;
    if (!(await isFile(path))) continue;
    const preamble = (await readFile(path, "utf8")).split(/(?<=\n)/).slice(0, 3).join("");
    if (!preamble.includes("Start at [index.md](index.md).")) {
      errors.push(`${path} must start with a backlink to docs/specs/index.md`);
    }
  }
}

async function checkMakeTargets() {
  const requiredTargets = ["test", "coverage", "coverage-html", "coverage-branch", "mutation", "vet"];
  const targets = new Set();
  const phony = new Set();
  for (const line of (await readFile("Makefile", "utf8")).split(/\n/)) {
    const phonyMatch = /^\.PHONY:\s+(.+?)\s*$/.exec(line);
    if (phonyMatch) {
      for (const target of phonyMatch[1].trim().split(/\s+/)) phony.add(target);
      continue;
    }
    const targetMatch = /^([A-Za-z0-9_.-]+):(?:\s|$)/.exec(line);
    if (targetMatch) targets.add(targetMatch[1]);
  }
  for (const target of requiredTargets) {
    if (!targets.has(target)) errors.push(`Makefile missing required testing target: ${target}`);
    if (!phony.has(target)) errors.push(`Makefile target must be .PHONY: ${target}`);
  }
}

async function checkMarkdownLint(file) {
  const content = await readFile(file, "utf8");
  const lines = content.split(/(?<=\n)/);
  let inFence = false;
  let fenceLine = 0;
  lines.forEach((line, index) => {
    const lineNumber = index + 1;
    if (/[ \t]\r?\n?$/.test(line)) errors.push(`${file}:${lineNumber} trailing whitespace`);
    if (line.includes("\t")) errors.push(`${file}:${lineNumber} tab character`);
    if (/^(```+|~~~+)/.test(line)) {
      if (inFence) {
        inFence = false;
        fenceLine = 0;
      } else {
        inFence = true;
        fenceLine = lineNumber;
      }
    }
  });
  if (content.length === 0) errors.push(`${file} is empty`);
  if (content.length > 0 && !content.endsWith("\n")) errors.push(`${file} missing final newline`);
  if (inFence) errors.push(`${file}:${fenceLine} unclosed fenced code block`);
}

async function walkMarkdown(root) {
  const out = [];
  async function walk(path) {
    for (const entry of await readdir(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      if (entry.isDirectory()) await walk(child);
      else if (entry.isFile() && entry.name.endsWith(".md")) out.push(child.split(posix.sep).join("/"));
    }
  }
  await walk(root);
  return out;
}

function dirname(path) {
  if (!path.includes("/")) return ".";
  const dir = path.replace(/\/[^/]+$/, "");
  return dir.length ? dir : ".";
}

function normalizePath(path) {
  const parts = [];
  for (const part of path.split(/\/+/)) {
    if (!part || part === ".") continue;
    if (part === "..") {
      if (parts.length > 0) parts.pop();
      continue;
    }
    parts.push(part);
  }
  return parts.join("/");
}

function uriDecode(value) {
  return value.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)));
}

function githubAnchor(heading) {
  return heading
    .replace(/`([^`]*)`/g, "$1")
    .toLowerCase()
    .replace(/[^a-z0-9 _-]/g, "")
    .replace(/\s+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function checkAnchor(file, anchor, anchorsByFile) {
  if (anchor == null || anchor === "") return true;
  return anchorsByFile.get(file)?.has(uriDecode(anchor).toLowerCase()) ?? false;
}

async function isFile(path) {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}
