import { jsPDF } from "jspdf";
import { autoTable } from "jspdf-autotable";
import type { Report, Severity } from "./types";
import { SEVERITY_ORDER } from "./types";

// A4 layout constants (mm)
const PAGE_W = 210;
const PAGE_H = 297;
const MARGIN = 14;
const CONTENT_W = PAGE_W - MARGIN * 2;

type Rgb = [number, number, number];

const INK: Rgb = [24, 24, 23];
const INK_2: Rgb = [90, 89, 84];
const MUTED: Rgb = [137, 135, 129];
const HAIRLINE: Rgb = [225, 224, 217];
const DARK_BAND: Rgb = [26, 26, 25];

const SEV: Record<Severity | "unknown", { label: string; rgb: Rgb }> = {
  critical: { label: "Critical", rgb: [208, 59, 59] },
  high: { label: "High", rgb: [220, 106, 58] },
  medium: { label: "Medium", rgb: [178, 124, 0] },
  low: { label: "Low", rgb: [42, 120, 214] },
  info: { label: "Info", rgb: [120, 118, 112] },
  unknown: { label: "Unrated", rgb: [120, 118, 112] },
};

function scoreRgb(score: number): Rgb {
  if (score >= 88) return [12, 131, 12];
  if (score >= 75) return [178, 124, 0];
  if (score >= 50) return [220, 106, 58];
  return [208, 59, 59];
}

interface Cursor {
  y: number;
}

function ensureRoom(doc: jsPDF, cursor: Cursor, needed: number) {
  if (cursor.y + needed > PAGE_H - 18) {
    doc.addPage();
    cursor.y = MARGIN + 4;
  }
}

function sectionTitle(doc: jsPDF, cursor: Cursor, title: string) {
  ensureRoom(doc, cursor, 18);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.setTextColor(...INK);
  doc.text(title, MARGIN, cursor.y);
  doc.setDrawColor(...HAIRLINE);
  doc.setLineWidth(0.3);
  doc.line(MARGIN, cursor.y + 2, PAGE_W - MARGIN, cursor.y + 2);
  cursor.y += 8;
}

function lastY(doc: jsPDF): number {
  return (doc as unknown as { lastAutoTable?: { finalY?: number } }).lastAutoTable?.finalY ?? MARGIN;
}

export function generatePdfReport(report: Report): void {
  buildPdfReport(report).save(`GitGuard-${report.repo.owner}-${report.repo.repo}.pdf`);
}

export function buildPdfReport(report: Report): jsPDF {
  const doc = new jsPDF({ unit: "mm", format: "a4" });
  const { repo, score } = report;
  const cursor: Cursor = { y: 0 };

  // ── Header band ────────────────────────────────────────────
  doc.setFillColor(...DARK_BAND);
  doc.rect(0, 0, PAGE_W, 30, "F");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(18);
  doc.setTextColor(255, 255, 255);
  doc.text("GitGuard", MARGIN, 13.5);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.setTextColor(195, 194, 183);
  doc.text("Repository Security Report", MARGIN, 20);
  doc.text(new Date(report.scannedAt).toUTCString(), PAGE_W - MARGIN, 13.5, { align: "right" });
  doc.text(
    `Scan duration: ${(report.durationMs / 1000).toFixed(1)}s`,
    PAGE_W - MARGIN,
    20,
    { align: "right" }
  );

  // ── Repository block ───────────────────────────────────────
  cursor.y = 42;
  doc.setFont("helvetica", "bold");
  doc.setFontSize(15);
  doc.setTextColor(...INK);
  doc.text(`${repo.owner}/${repo.repo}`, MARGIN, cursor.y);
  cursor.y += 6;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.setTextColor(...INK_2);
  doc.text(repo.url, MARGIN, cursor.y);
  cursor.y += 5;
  if (repo.description) {
    const desc = doc.splitTextToSize(repo.description, CONTENT_W - 60);
    doc.setTextColor(...MUTED);
    doc.text(desc, MARGIN, cursor.y);
    cursor.y += desc.length * 4.2 + 1;
  }
  const metaBits = [
    `${report.filesScanned} of ${report.filesTotal} files scanned`,
    `${report.dependencies.length} dependencies analyzed`,
    `AI review: ${report.aiAnalyzed ? "enabled" : "not run"}`,
  ];
  if (repo.language) metaBits.unshift(repo.language);
  doc.setTextColor(...MUTED);
  doc.text(metaBits.join("   ·   "), MARGIN, cursor.y);

  // ── Score box (top right) ──────────────────────────────────
  const boxW = 52;
  const boxX = PAGE_W - MARGIN - boxW;
  const boxY = 38;
  const sColor = scoreRgb(score.score);
  doc.setDrawColor(...HAIRLINE);
  doc.setLineWidth(0.4);
  doc.roundedRect(boxX, boxY, boxW, 26, 2, 2, "S");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(22);
  doc.setTextColor(...sColor);
  doc.text(String(score.score), boxX + 8, boxY + 13);
  doc.setFontSize(8);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(...MUTED);
  doc.text("/ 100", boxX + 8 + doc.getTextWidth(String(score.score)) + 7, boxY + 13);
  doc.text("SECURITY SCORE", boxX + 8, boxY + 18.5);
  // Grade chip
  doc.setFillColor(...sColor);
  doc.roundedRect(boxX + boxW - 16, boxY + 5, 10, 10, 1.5, 1.5, "F");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.setTextColor(255, 255, 255);
  doc.text(score.grade, boxX + boxW - 11, boxY + 11.5, { align: "center" });
  // Meter bar
  doc.setFillColor(235, 234, 228);
  doc.roundedRect(boxX + 8, boxY + 21, boxW - 16, 1.8, 0.9, 0.9, "F");
  doc.setFillColor(...sColor);
  doc.roundedRect(boxX + 8, boxY + 21, Math.max(2, (boxW - 16) * (score.score / 100)), 1.8, 0.9, 0.9, "F");

  cursor.y = Math.max(cursor.y + 10, boxY + 26 + 12);

  // ── Summary table ──────────────────────────────────────────
  sectionTitle(doc, cursor, "Summary");
  const sevKeys = ["critical", "high", "medium", "low", "info", "unknown"] as const;
  const summaryRows = sevKeys
    .map((key) => {
      const code = report.findings.filter((f) => f.severity === key).length;
      const cve = report.cves.filter((c) => c.severity === key).length;
      return { key, code, cve };
    })
    .filter((r) => r.code + r.cve > 0)
    .map((r) => [SEV[r.key].label, String(r.code), String(r.cve), String(r.code + r.cve)]);

  if (summaryRows.length === 0) {
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.setTextColor(12, 131, 12);
    doc.text("No issues detected — clean bill of health.", MARGIN, cursor.y);
    cursor.y += 8;
  } else {
    autoTable(doc, {
      startY: cursor.y,
      margin: { left: MARGIN, right: MARGIN },
      head: [["Severity", "Code findings", "CVEs", "Total"]],
      body: summaryRows,
      theme: "grid",
      styles: { fontSize: 8.5, textColor: INK, lineColor: HAIRLINE, lineWidth: 0.2, cellPadding: 2 },
      headStyles: { fillColor: DARK_BAND, textColor: [255, 255, 255], fontStyle: "bold" },
      tableWidth: 120,
      columnStyles: {
        0: { fontStyle: "bold", cellWidth: 36 },
        1: { halign: "right", cellWidth: 34 },
        2: { halign: "right", cellWidth: 26 },
        3: { halign: "right", fontStyle: "bold", cellWidth: 24 },
      },
      didParseCell: (data) => {
        if (data.section === "body" && data.column.index === 0) {
          const entry = Object.values(SEV).find((s) => s.label === data.cell.raw);
          if (entry) data.cell.styles.textColor = entry.rgb;
        }
      },
    });
    cursor.y = lastY(doc) + 8;

    if (score.deductions.length > 0) {
      ensureRoom(doc, cursor, 6 + score.deductions.length * 4.5);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(9);
      doc.setTextColor(...INK);
      doc.text("Score breakdown (starting from 100):", MARGIN, cursor.y);
      cursor.y += 5;
      doc.setFont("helvetica", "normal");
      doc.setFontSize(8.5);
      doc.setTextColor(...INK_2);
      for (const d of score.deductions) {
        // ASCII hyphen: the U+2212 minus sign is missing from jsPDF's built-in fonts
        doc.text(`-${d.points} pts   ${d.label}`, MARGIN + 3, cursor.y);
        cursor.y += 4.5;
      }
      cursor.y += 4;
    }
  }

  // ── Code findings ──────────────────────────────────────────
  const findings = [...report.findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
  );
  sectionTitle(doc, cursor, `Code findings (${findings.length})`);
  if (findings.length === 0) {
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.setTextColor(...MUTED);
    doc.text("No code-level findings.", MARGIN, cursor.y);
    cursor.y += 8;
  } else {
    autoTable(doc, {
      startY: cursor.y,
      margin: { left: MARGIN, right: MARGIN },
      head: [["Severity", "Finding", "Location"]],
      body: findings.map((f) => [
        SEV[f.severity].label,
        `${f.title}${f.source === "ai" ? "  [AI]" : ""}\n${f.description}\nFix: ${f.remediation}`,
        `${f.file}:${f.line}`,
      ]),
      theme: "grid",
      styles: { fontSize: 7.5, textColor: INK_2, lineColor: HAIRLINE, lineWidth: 0.2, cellPadding: 2, valign: "top" },
      headStyles: { fillColor: DARK_BAND, textColor: [255, 255, 255], fontStyle: "bold", fontSize: 8.5 },
      columnStyles: {
        0: { cellWidth: 20, fontStyle: "bold" },
        1: { cellWidth: 110 },
        2: { cellWidth: CONTENT_W - 130, font: "courier", fontSize: 7 },
      },
      didParseCell: (data) => {
        if (data.section !== "body") return;
        if (data.column.index === 0) {
          const entry = Object.values(SEV).find((s) => s.label === data.cell.raw);
          if (entry) data.cell.styles.textColor = entry.rgb;
        }
      },
    });
    cursor.y = lastY(doc) + 10;
  }

  // ── Known CVEs ─────────────────────────────────────────────
  const cves = [...report.cves].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
  );
  sectionTitle(doc, cursor, `Known CVEs (${cves.length})`);
  if (cves.length === 0) {
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.setTextColor(...MUTED);
    doc.text("No known CVEs in the analyzed dependencies.", MARGIN, cursor.y);
    cursor.y += 8;
  } else {
    autoTable(doc, {
      startY: cursor.y,
      margin: { left: MARGIN, right: MARGIN },
      head: [["ID", "Severity", "Package", "Installed", "Fixed in", "Summary"]],
      body: cves.map((c) => [
        c.cveId ?? c.id,
        SEV[c.severity].label,
        c.package,
        c.installedVersion,
        c.fixedVersion ?? "—",
        c.summary,
      ]),
      theme: "grid",
      styles: { fontSize: 7, textColor: INK_2, lineColor: HAIRLINE, lineWidth: 0.2, cellPadding: 1.8, valign: "top" },
      headStyles: { fillColor: DARK_BAND, textColor: [255, 255, 255], fontStyle: "bold", fontSize: 8 },
      columnStyles: {
        0: { cellWidth: 33, font: "courier", fontSize: 6.5 },
        1: { cellWidth: 17, fontStyle: "bold" },
        2: { cellWidth: 28 },
        3: { cellWidth: 17 },
        4: { cellWidth: 17 },
      },
      didParseCell: (data) => {
        if (data.section === "body" && data.column.index === 1) {
          const entry = Object.values(SEV).find((s) => s.label === data.cell.raw);
          if (entry) data.cell.styles.textColor = entry.rgb;
        }
      },
    });
  }

  // ── Footer on every page ───────────────────────────────────
  const pages = doc.getNumberOfPages();
  for (let i = 1; i <= pages; i++) {
    doc.setPage(i);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(7.5);
    doc.setTextColor(...MUTED);
    doc.text("Generated by GitGuard — pattern analysis · OSV.dev CVE data · AI code review", MARGIN, PAGE_H - 8);
    doc.text(`${i} / ${pages}`, PAGE_W - MARGIN, PAGE_H - 8, { align: "right" });
  }

  return doc;
}
