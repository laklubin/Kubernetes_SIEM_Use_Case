#!/usr/bin/env node
/*
 * Regenerates data/usecases.json, data/usecases.csv and the use case table in README.md
 * from assets/js/usecases.js (the single source of truth).
 *
 *   node tools/build-data.js
 */
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const root = path.join(__dirname, "..");
const ctx = { window: {} };
vm.runInNewContext(fs.readFileSync(path.join(root, "assets/js/usecases.js"), "utf8"), ctx);
const DATA = ctx.window.USE_CASES;

const logOneLine = (l) => (typeof l === "string" ? l : JSON.stringify(l));
const mitreUrl = (id) => "https://attack.mitre.org/techniques/" + id.replace(".", "/") + "/";

// JSON
fs.writeFileSync(path.join(root, "data/usecases.json"), JSON.stringify(DATA, null, 2) + "\n");

// CSV
const cell = (v) => {
  v = String(v);
  return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
};
const header = ["ID", "Use Case Name", "Category", "Severity", "Confidence Score", "Log Sources", "MITRE Tactics",
  "MITRE Techniques", "Description", "Detection Logic", "False Positives", "Sample Log"];
const csv = [header.join(",")].concat(DATA.map((u) => [
  u.id, u.name, u.category, u.severity, u.confidence, u.logSources.join("; "), u.tactics.join("; "),
  u.mitre.map((m) => m.id + " " + m.name).join("; "), u.description, u.detection, u.falsePositives, logOneLine(u.sampleLog)
].map(cell).join(",")));
fs.writeFileSync(path.join(root, "data/usecases.csv"), csv.join("\r\n") + "\r\n");

// README table
const md = (s) => String(s).replace(/\|/g, "\\|");
const rows = DATA.map((u) => "| " + [
  u.id,
  md(u.name),
  u.severity,
  md(u.logSources.join("<br>")),
  u.confidence,
  u.mitre.map((m) => `[${m.id}](${mitreUrl(m.id)})`).join(", ")
].join(" | ") + " |");
const table = [
  "| ID | Use Case Name | Severity | Log Source | Confidence | MITRE ATT&CK |",
  "|----|---------------|----------|------------|-----------:|--------------|"
].concat(rows).join("\n");

const readmePath = path.join(root, "README.md");
const readme = fs.readFileSync(readmePath, "utf8");
const start = "<!-- USE-CASES:START -->";
const end = "<!-- USE-CASES:END -->";
const i = readme.indexOf(start);
const j = readme.indexOf(end);
if (i === -1 || j === -1) throw new Error("README markers not found");
fs.writeFileSync(readmePath, readme.slice(0, i + start.length) + "\n" + table + "\n" + readme.slice(j));

console.log(`Wrote ${DATA.length} use cases to data/usecases.json, data/usecases.csv and README.md`);
