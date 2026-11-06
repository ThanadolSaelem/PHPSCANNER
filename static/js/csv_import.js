"use strict";

(function (root, factory) {
  if (typeof define === "function" && define.amd) {
    define([], factory);
  } else if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.ThscanCsvImport = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  const MAX_ROWS = 200000;
  const IPV4_SHAPE_REGEX = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  const IPV6_HINT_REGEX = /^[0-9a-fA-F:]+:[0-9a-fA-F:]+$/;
  const HEADER_NAMES = new Set([
    "ip",
    "ip address",
    "ip_address",
    "ip-address",
    "ipaddress",
    "ipv4",
    "ipv4 address",
    "host",
    "target",
  ]);

  function canonicalIPv4(value) {
    const str = String(value ?? "").trim();
    if (!IPV4_SHAPE_REGEX.test(str)) return null;
    const parts = str.split(".").map((v) => parseInt(v, 10));
    if (parts.some((n) => isNaN(n) || n < 0 || n > 255)) return null;
    return parts.join(".");
  }

  function classifyInvalidIp(raw) {
    const val = String(raw ?? "").trim();
    if (!val) return { kind: "empty", label: "ไม่มีข้อมูล IP" };
    if (IPV6_HINT_REGEX.test(val) && val.includes(":")) {
      return { kind: "ipv6", label: "เป็นรูปแบบ IPv6" };
    }
    return { kind: "invalid", label: "ไม่ใช่ IPv4 ที่ถูกต้อง" };
  }

  function parseCsvIpTargets(text, options) {
    if (typeof text !== "string") {
      throw new Error("ข้อมูล CSV ต้องเป็นข้อความ");
    }
    const opts = options || {};
    const allowSkipInvalid = !!opts.allowSkipInvalid;

    const cleanText = text.replace(/^\uFEFF/, "");
    const targets = [];
    const seen = new Set();
    const skippedRows = [];
    let hasHeader = false;
    let columnIndex = 0;
    let duplicateCount = 0;
    let blankRowCount = 0;
    let totalValidRows = 0;
    let physicalRow = 0;

    let index = 0;
    const len = cleanText.length;

    while (index < len) {
      physicalRow++;
      if (physicalRow > MAX_ROWS) {
        throw new Error(`ไฟล์ CSV มีจำนวนแถวเกิน ${MAX_ROWS.toLocaleString("en-US")} แถว`);
      }

      const cells = [];
      let currentCell = "";
      let inQuotes = false;

      while (index < len) {
        const char = cleanText[index];

        if (inQuotes) {
          if (char === '"') {
            if (index + 1 < len && cleanText[index + 1] === '"') {
              currentCell += '"';
              index += 2;
              continue;
            } else {
              inQuotes = false;
              index++;
              continue;
            }
          }
          currentCell += char;
          index++;
        } else {
          if (char === '"') {
            inQuotes = true;
            index++;
          } else if (char === ",") {
            cells.push(currentCell);
            currentCell = "";
            index++;
          } else if (char === "\r") {
            if (index + 1 < len && cleanText[index + 1] === "\n") {
              index++;
            }
            index++;
            break;
          } else if (char === "\n") {
            index++;
            break;
          } else {
            currentCell += char;
            index++;
          }
        }
      }

      if (inQuotes) {
        throw new Error(`ข้อผิดพลาด CSV รูปแบบเครื่องหมายคำพูดไม่ถูกต้อง แถว ${physicalRow}`);
      }

      cells.push(currentCell);

      if (cells.length === 1 && cells[0].trim() === "") {
        blankRowCount++;
        continue;
      }

      if (physicalRow === 1) {
        const headerIdx = cells.findIndex((cell) => HEADER_NAMES.has(cell.trim().toLowerCase()));
        if (headerIdx !== -1) {
          hasHeader = true;
          columnIndex = headerIdx;
          continue;
        }
      }

      const rawIp = cells[columnIndex] !== undefined ? cells[columnIndex].trim() : "";
      const canonicalIp = canonicalIPv4(rawIp);
      if (!canonicalIp) {
        const info = classifyInvalidIp(rawIp);
        if (!allowSkipInvalid) {
          const reason = rawIp ? "ไม่ใช่ IPv4 ที่ถูกต้อง" : "ไม่มีข้อมูล IP";
          throw new Error(`แถว ${physicalRow}: ${reason} ในคอลัมน์ IP — ยกเลิกการนำเข้าทั้งไฟล์`);
        }
        skippedRows.push({
          row: physicalRow,
          value: rawIp || "(ว่าง)",
          kind: info.kind,
          reason: info.label,
        });
        continue;
      }

      totalValidRows++;
      if (seen.has(canonicalIp)) {
        duplicateCount++;
      } else {
        seen.add(canonicalIp);
        targets.push(canonicalIp);
      }
    }

    if (targets.length === 0) {
      throw new Error("ไม่พบ IPv4 ที่ถูกต้องใน CSV");
    }

    return {
      targets: targets,
      totalValidRows: totalValidRows,
      hasHeader: hasHeader,
      columnIndex: columnIndex,
      duplicates: duplicateCount,
      blankRows: blankRowCount,
      skippedRows: skippedRows,
    };
  }

  function buildCleanCsvText(targets, headerName) {
    const hdr = headerName || "ip";
    return "\uFEFF" + [hdr, ...(targets || [])].join("\r\n") + "\r\n";
  }

  return {
    MAX_ROWS: MAX_ROWS,
    canonicalIPv4: canonicalIPv4,
    parseCsvIpTargets: parseCsvIpTargets,
    buildCleanCsvText: buildCleanCsvText,
  };
});
