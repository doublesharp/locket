#!/usr/bin/env node
import { readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import process from "node:process";

const [metadataPath, reportPath] = process.argv.slice(2);
if (!metadataPath || !reportPath) {
  console.error("usage: unsafe-inventory-fallback.mjs <cargo-metadata.json> <report.md>");
  process.exit(2);
}

const metadata = JSON.parse(await readFile(metadataPath, "utf8"));
const workspaceMembers = new Set(metadata.workspace_members ?? []);
const rows = [];

for (const pkg of metadata.packages ?? []) {
  if (!pkg.manifest_path) continue;
  const root = dirname(pkg.manifest_path);
  const counts = await countUnsafeTokens(root);
  rows.push({
    name: pkg.name,
    version: pkg.version,
    scope: workspaceMembers.has(pkg.id) ? "workspace" : "dependency",
    files: counts.files,
    tokens: counts.tokens,
  });
}

rows.sort((a, b) => {
  if (a.scope !== b.scope) return a.scope === "workspace" ? -1 : 1;
  return a.name.localeCompare(b.name) || a.version.localeCompare(b.version);
});

const totalFiles = rows.reduce((sum, row) => sum + row.files, 0);
const totalTokens = rows.reduce((sum, row) => sum + row.tokens, 0);

const lines = [
  "# Unsafe Inventory",
  "",
  "- Tool: lexical unsafe-token inventory fallback",
  "- Scope: Cargo.lock packages from cargo metadata --offline --locked",
  "- Metadata: target/quality/cargo-metadata.json",
  "- Review trigger: run before public releases and after crypto, IPC, platform-verification, or storage dependency changes.",
  "- Note: fallback counts `unsafe` tokens in Rust source and does not classify callsites like cargo-geiger.",
  "",
  "| Package | Version | Scope | Rust files | unsafe tokens |",
  "| --- | --- | --- | ---: | ---: |",
];
for (const row of rows) {
  lines.push(`| ${row.name} | ${row.version} | ${row.scope} | ${row.files} | ${row.tokens} |`);
}
lines.push("");
lines.push(`Total Rust files: ${totalFiles}`);
lines.push("");
lines.push(`Total unsafe tokens: ${totalTokens}`);
lines.push("");

await writeFile(reportPath, lines.join("\n"));
console.log(`wrote ${reportPath}`);

async function countUnsafeTokens(root) {
  let files = 0;
  let tokens = 0;
  async function walk(dir) {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(path);
      } else if (entry.isFile() && entry.name.endsWith(".rs")) {
        files++;
        const text = await readFile(path, "utf8");
        tokens += text.match(/\bunsafe\b/g)?.length ?? 0;
      }
    }
  }
  await walk(root);
  return { files, tokens };
}
