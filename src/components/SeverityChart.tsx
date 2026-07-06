"use client";

import { useState } from "react";
import { Table2, BarChart3 } from "lucide-react";
import type { CveFinding, Finding, Severity } from "@/lib/types";
import { SEVERITY, SEVERITY_KEYS } from "./severity";

// Horizontal bar chart of findings by severity. Status palette (severity IS the
// meaning), icon + label so identity never relies on color, thin bars with a
// 4px rounded data-end, value direct-labeled at the tip, and a table-view twin.

interface Row {
  key: Severity | "unknown";
  code: number;
  cve: number;
  total: number;
}

export function SeverityChart({
  findings,
  cves,
}: {
  findings: Finding[];
  cves: CveFinding[];
}) {
  const [view, setView] = useState<"chart" | "table">("chart");

  const rows: Row[] = SEVERITY_KEYS.map((key) => {
    const code = findings.filter((f) => f.severity === key).length;
    const cve = key === "info" ? 0 : cves.filter((c) => c.severity === key).length;
    return { key, code, cve, total: code + cve };
  });
  const unrated = cves.filter((c) => c.severity === "unknown").length;
  if (unrated > 0) rows.push({ key: "unknown", code: 0, cve: unrated, total: unrated });

  const max = Math.max(1, ...rows.map((r) => r.total));

  return (
    <div className="rounded-xl border border-[var(--color-hairline)] bg-[var(--color-surface)] p-5">
      <div className="mb-4 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-[var(--color-ink)]">
          Findings by severity
        </h3>
        <button
          onClick={() => setView(view === "chart" ? "table" : "chart")}
          className="inline-flex items-center gap-1.5 rounded-md border border-[var(--color-hairline)] px-2 py-1 text-xs text-[var(--color-ink-2)] transition-colors hover:bg-[var(--color-raised)]"
        >
          {view === "chart" ? <Table2 className="h-3.5 w-3.5" /> : <BarChart3 className="h-3.5 w-3.5" />}
          {view === "chart" ? "Table" : "Chart"}
        </button>
      </div>

      {view === "chart" ? (
        <div className="flex flex-col gap-2.5">
          {rows.map((row) => {
            const s = SEVERITY[row.key];
            const Icon = s.icon;
            const widthPct = (row.total / max) * 100;
            return (
              <div key={row.key} className="flex items-center gap-3">
                <div className="flex w-20 shrink-0 items-center gap-1.5 text-xs text-[var(--color-ink-2)]">
                  <Icon className="h-3.5 w-3.5 shrink-0" style={{ color: s.color }} aria-hidden />
                  {s.label}
                </div>
                <div className="relative h-4 flex-1">
                  <div
                    className="absolute inset-y-0 left-0 rounded-[4px]"
                    style={{
                      width: `${Math.max(widthPct, row.total > 0 ? 3 : 0)}%`,
                      minWidth: row.total > 0 ? 8 : 0,
                      backgroundColor: s.color,
                      transition: "width 0.5s cubic-bezier(0.22,1,0.36,1)",
                    }}
                  />
                </div>
                <span className="w-6 shrink-0 text-right text-sm font-semibold tabular-nums text-[var(--color-ink)]">
                  {row.total}
                </span>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-hairline)] text-left text-xs text-[var(--color-muted)]">
                <th className="pb-2 font-medium">Severity</th>
                <th className="pb-2 text-right font-medium">Code</th>
                <th className="pb-2 text-right font-medium">CVE</th>
                <th className="pb-2 text-right font-medium">Total</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.key} className="border-b border-[var(--color-hairline)] last:border-0">
                  <td className="py-1.5">
                    <span className="inline-flex items-center gap-1.5" style={{ color: SEVERITY[row.key].color }}>
                      {SEVERITY[row.key].label}
                    </span>
                  </td>
                  <td className="py-1.5 text-right tabular-nums text-[var(--color-ink-2)]">{row.code}</td>
                  <td className="py-1.5 text-right tabular-nums text-[var(--color-ink-2)]">{row.cve}</td>
                  <td className="py-1.5 text-right font-semibold tabular-nums text-[var(--color-ink)]">{row.total}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
