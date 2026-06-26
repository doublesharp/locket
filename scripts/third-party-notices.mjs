#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import process from "node:process";

const [metadataPath, reportPath] = process.argv.slice(2);

if (!metadataPath || !reportPath) {
  console.error("usage: third-party-notices.mjs <cargo-metadata.json> <report.md>");
  process.exit(2);
}

const metadata = JSON.parse(await readFile(metadataPath, "utf8"));
const packages = Array.isArray(metadata.packages) ? metadata.packages : [];

const mplPackages = packages
  .filter((pkg) => pkg.source != null && /\bMPL-2\.0\b/.test(pkg.license ?? ""))
  .sort((a, b) => {
    const byName = String(a.name ?? "").localeCompare(String(b.name ?? ""));
    if (byName !== 0) return byName;
    return String(a.version ?? "").localeCompare(String(b.version ?? ""));
  });

await writeFile(reportPath, renderReport(mplPackages));
console.log(`wrote ${reportPath}`);

function renderReport(packages) {
  const generated = new Date().toISOString().slice(0, 10);
  const lines = [
    "# Third-party Notices",
    "",
    `- Generated: ${generated}`,
    "- Scope: Rust crates from `cargo metadata --offline --locked`.",
    "- Purpose: MPL-2.0 source-availability and notice tracking for distributed Locket artifacts.",
    "",
    "This distribution includes unmodified MPL-2.0 covered third-party crates. Locket is distributed as a larger work under its own license; the crates listed below remain available under MPL-2.0. If Locket ever vendors or patches one of these crates, the modified MPL-covered files must also be made available under MPL-2.0.",
    "",
    "## MPL-2.0 Covered Crates",
    "",
  ];

  if (packages.length === 0) {
    lines.push("No MPL-2.0 covered Rust crates were found in the resolved dependency metadata.");
  } else {
    for (const pkg of packages) {
      const source = sourceUrl(pkg);
      const repository = pkg.repository ?? "";
      lines.push(`### ${markdownEscape(pkg.name)} ${markdownEscape(pkg.version)}`);
      lines.push("");
      lines.push(`- License: ${markdownEscape(pkg.license)}`);
      if (source) lines.push(`- Source: ${markdownEscape(source)}`);
      if (repository && repository !== source) {
        lines.push(`- Repository: ${markdownEscape(repository)}`);
      }
      lines.push("- Modification status: unmodified third-party crate from the resolved Cargo dependency graph.");
      lines.push("");
    }
  }

  lines.push("## MPL-2.0 License Text");
  lines.push("");
  lines.push("The full Mozilla Public License 2.0 text is available at https://mozilla.org/MPL/2.0/.");
  lines.push("");
  return `${lines.join("\n")}`;
}

function sourceUrl(pkg) {
  if (String(pkg.source ?? "").startsWith("registry+")) {
    return `https://crates.io/crates/${pkg.name}/${pkg.version}`;
  }
  return pkg.repository ?? "";
}

function markdownEscape(value) {
  return String(value ?? "").replaceAll("|", "\\|").replace(/\r?\n/g, " ");
}
