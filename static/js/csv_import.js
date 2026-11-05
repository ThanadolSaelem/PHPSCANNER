/* Local-only CSV import parser for thscan. No network or file persistence. */
(function (root) {
  "use strict";

  const HEADER_NAMES = new Set(["ip", "ip address", "ip_address", "ip-address", "ipaddress", "ipv4", "ipv4 address"]);
  const MAX_ROWS = 200000;

  function canonicalIPv4(value) {
    const text = String(value ?? "").trim();
    const parts = text.split(".");
    if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return null;
    return parts.map((part) => String(Number(part))).join(".");
  }

  function parseCsvIpTargets(text) {
    if (typeof text !== "string") throw new Error("อ่านเนื้อหา CSV ไม่ได้");
    if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);

    let cell = "", row = [], quoted = false, quoteClosed = false;
    let physicalRow = 0, dataRows = 0, columnIndex = null;
    let hasHeader = false, duplicates = 0, blankRows = 0;
    const targets = [], seen = new Set();

    function consumeRow() {
      physicalRow += 1;
      if (physicalRow > MAX_ROWS) throw new Error(`ไฟล์มีเกิน ${MAX_ROWS.toLocaleString("en-US")} แถวที่รองรับ`);
      const cells = row;
      row = [];
      const nonempty = cells.some((value) => value.trim() !== "");
      if (!nonempty) { blankRows += 1; return; }

      if (columnIndex === null) {
        const headerIndex = cells.findIndex((value) => HEADER_NAMES.has(value.trim().toLowerCase().replace(/\s+/g, " ")));
        if (headerIndex >= 0) {
          columnIndex = headerIndex;
          hasHeader = true;
          return;
        }
        columnIndex = 0; // Headerless files use the first column.
      }

      const ip = canonicalIPv4(cells[columnIndex] ?? "");
      if (!ip) {
        const reason = (cells[columnIndex] ?? "").trim() ? "ไม่ใช่ IPv4 ที่ถูกต้อง" : "ไม่มีค่า IP";
        throw new Error(`แถว ${physicalRow}: ${reason} ในคอลัมน์ IP — ยกเลิกการนำเข้าทั้งไฟล์`);
      }
      dataRows += 1;
      if (seen.has(ip)) duplicates += 1;
      else { seen.add(ip); targets.push(ip); }
    }

    for (let i = 0; i < text.length; i += 1) {
      const ch = text[i];
      if (quoted) {
        if (ch === '"') {
          if (text[i + 1] === '"') { cell += '"'; i += 1; }
          else { quoted = false; quoteClosed = true; }
        } else cell += ch;
        continue;
      }
      if (quoteClosed && ch !== "," && ch !== "\r" && ch !== "\n" && !/[ \t]/.test(ch)) {
        throw new Error(`CSV รูปแบบไม่ถูกต้องใกล้แถว ${physicalRow + 1}`);
      }
      if (ch === '"') {
        if (cell.length || quoteClosed) throw new Error(`CSV รูปแบบไม่ถูกต้องใกล้แถว ${physicalRow + 1}`);
        quoted = true;
      } else if (ch === ",") {
        row.push(cell); cell = ""; quoteClosed = false;
      } else if (ch === "\r" || ch === "\n") {
        row.push(cell); cell = ""; quoteClosed = false;
        consumeRow();
        if (ch === "\r" && text[i + 1] === "\n") i += 1;
      } else {
        cell += ch;
      }
    }
    if (quoted) throw new Error("CSV มีเครื่องหมายอัญประกาศไม่ครบ");
    if (cell.length || row.length || quoteClosed) {
      row.push(cell);
      consumeRow();
    }
    if (!targets.length) throw new Error("ไม่พบ IPv4 ในไฟล์ CSV");
    return { targets, rows: dataRows, duplicates, blankRows, hasHeader, columnIndex };
  }

  const api = { parseCsvIpTargets, MAX_ROWS };
  root.ThscanCsvImport = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(globalThis);
