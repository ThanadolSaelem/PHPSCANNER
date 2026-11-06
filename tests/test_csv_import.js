"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { parseCsvIpTargets, buildCleanCsvText, MAX_ROWS } = require("../static/js/csv_import.js");

test("reads a named IP Address column and skips metadata columns", () => {
  const parsed = parseCsvIpTargets('Organization,"IP Address",Port\r\nExample,"10.0.0.1",443\r\nOther,10.0.0.2,80\r\n');
  assert.deepEqual(parsed.targets, ["10.0.0.1", "10.0.0.2"]);
  assert.equal(parsed.hasHeader, true);
  assert.equal(parsed.columnIndex, 1);
});

test("headerless files use the first column and deduplicate canonical IPv4", () => {
  const parsed = parseCsvIpTargets("010.000.000.001,metadata\n10.0.0.1,again\n10.0.0.2,third");
  assert.deepEqual(parsed.targets, ["10.0.0.1", "10.0.0.2"]);
  assert.equal(parsed.duplicates, 1);
  assert.equal(parsed.hasHeader, false);
});

test("supports BOM, quoted commas, blank lines, and CRLF", () => {
  const parsed = parseCsvIpTargets('\uFEFFIP,Note\r\n10.1.2.3,"comma, inside"\r\n\r\n');
  assert.deepEqual(parsed.targets, ["10.1.2.3"]);
  assert.equal(parsed.blankRows, 1);
});

test("rejects invalid IPv4 rows rather than silently skipping them in default strict mode", () => {
  assert.throws(() => parseCsvIpTargets("IP\n10.0.0.1\n999.1.1.1\n"), /แถว 3/);
  assert.throws(() => parseCsvIpTargets("IP\n10.0.0.1\n,missing\n"), /แถว 3/);
});

test("allowSkipInvalid mode filters out IPv6 and invalid rows while collecting skippedRows stats", () => {
  const csv = "ip\n10.0.0.1\n2001:3c8:2808:2::202\n10.0.0.2\n10.0.0.1\ninvalid_host\n";
  const parsed = parseCsvIpTargets(csv, { allowSkipInvalid: true });
  assert.deepEqual(parsed.targets, ["10.0.0.1", "10.0.0.2"]);
  assert.equal(parsed.totalValidRows, 3);
  assert.equal(parsed.duplicates, 1);
  assert.equal(parsed.skippedRows.length, 2);
  assert.equal(parsed.skippedRows[0].row, 3);
  assert.equal(parsed.skippedRows[0].kind, "ipv6");
  assert.equal(parsed.skippedRows[1].row, 6);
  assert.equal(parsed.skippedRows[1].kind, "invalid");
  const clean = buildCleanCsvText(parsed.targets);
  assert.ok(clean.includes("10.0.0.1\r\n10.0.0.2"));
});

test("rejects malformed quoting and empty datasets", () => {
  assert.throws(() => parseCsvIpTargets('IP\n"10.0.0.1\n'), /ข้อผิดพลาด CSV รูปแบบ/);
  assert.throws(() => parseCsvIpTargets("IP\n\n"), /ไม่พบ IPv4/);
});

test("enforces a maximum row count", () => {
  const overLimit = `IP\n${"10.0.0.1\n".repeat(MAX_ROWS)}`;
  assert.throws(() => parseCsvIpTargets(overLimit), /เกิน 200,000 แถว/);
});
