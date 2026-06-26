#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import process from "node:process";

const [ledgerPath, reportPath] = process.argv.slice(2);
if (!ledgerPath || !reportPath) {
  console.error("usage: supply-chain-exceptions.mjs <ledger.json> <report.md>");
  process.exit(2);
}

const today = process.env.LOCKET_TODAY ?? new Date().toISOString().slice(0, 10);
const ledger = JSON.parse(await readFile(ledgerPath, "utf8"));
if (!Array.isArray(ledger.exceptions)) {
  throw new Error("supply-chain exception ledger must contain an exceptions array");
}

const rows = [];
const errors = [];

ledger.exceptions.forEach((entry, offset) => {
  const index = offset + 1;
  if (!isObject(entry)) {
    errors.push(`exception ${index} must be an object`);
    return;
  }

  const entryErrors = [];
  for (const field of ["package", "version", "reason", "owner", "expires_at"]) {
    if (!nonEmptyString(entry[field])) entryErrors.push(`${field} is required`);
  }

  if (!Array.isArray(entry.compensating_controls) || entry.compensating_controls.length === 0) {
    entryErrors.push("compensating_controls must be a non-empty array");
  } else {
    for (const control of entry.compensating_controls) {
      if (!nonEmptyString(control)) {
        entryErrors.push("compensating_controls entries must be non-empty strings");
      }
    }
  }

  if (nonEmptyString(entry.expires_at)) {
    if (!validYmd(entry.expires_at)) {
      entryErrors.push("expires_at must be YYYY-MM-DD");
    } else if (entry.expires_at < today) {
      entryErrors.push(`expires_at is before ${today}`);
    }
  }

  for (const error of entryErrors) errors.push(`exception ${index}: ${error}`);
  rows.push({
    package: entry.package ?? "",
    version: entry.version ?? "",
    owner: entry.owner ?? "",
    expires_at: entry.expires_at ?? "",
    status: entryErrors.length ? "invalid" : "valid",
  });
});

await writeFile(reportPath, renderReport(rows, errors, today));

if (errors.length > 0) {
  console.error(`supply-chain exception ledger failed; see ${reportPath}`);
  for (const error of errors) console.error(` - ${error}`);
  process.exit(1);
}

console.log(`supply-chain exception ledger passed; see ${reportPath}`);

function isObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function nonEmptyString(value) {
  return typeof value === "string" && /\S/.test(value);
}

function validYmd(value) {
  const match = /^([0-9]{4})-([0-9]{2})-([0-9]{2})$/.exec(value);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (month < 1 || month > 12 || day < 1 || day > 31) return false;
  const date = new Date(Date.UTC(year, month - 1, day));
  return date.getUTCFullYear() === year
    && date.getUTCMonth() === month - 1
    && date.getUTCDate() === day;
}

function renderReport(rows, errors, checkedDate) {
  const lines = [
    "# Supply-chain Exception Ledger",
    "",
    `- Checked date: ${checkedDate}`,
    "- Required fields: package, version, reason, compensating_controls, owner, expires_at.",
    "- Expired entries and entries without expiration are invalid.",
    "",
    "| Package | Version | Owner | Expires | Status |",
    "| --- | --- | --- | --- | --- |",
  ];
  for (const row of rows) {
    lines.push(`| ${[row.package, row.version, row.owner, row.expires_at, row.status].map(markdownEscape).join(" | ")} |`);
  }
  lines.push("");
  if (errors.length > 0) {
    lines.push("Errors:");
    for (const error of errors) lines.push(`- ${error}`);
  } else {
    lines.push("Errors: none");
  }
  lines.push("");
  return lines.join("\n");
}

function markdownEscape(value) {
  return String(value ?? "").replaceAll("|", "\\|").replace(/\r?\n/g, " ");
}
