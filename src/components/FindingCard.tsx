import { Sparkles, ScanSearch, Wrench, FileCode2 } from "lucide-react";
import type { Finding } from "@/lib/types";
import { SeverityBadge } from "./severity";

export function FindingCard({ finding }: { finding: Finding }) {
  return (
    <div className="rise rounded-xl border border-[var(--color-hairline)] bg-[var(--color-surface)] p-4 transition-colors hover:border-[var(--color-hairline-strong)]">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-[var(--color-ink)]">{finding.title}</span>
          <span
            className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide"
            style={
              finding.source === "ai"
                ? { color: "#9085e9", backgroundColor: "#9085e920", border: "1px solid #9085e955" }
                : { color: "#898781", backgroundColor: "#89878118", border: "1px solid #89878144" }
            }
          >
            {finding.source === "ai" ? (
              <><Sparkles className="h-3 w-3" /> AI</>
            ) : (
              <><ScanSearch className="h-3 w-3" /> Pattern</>
            )}
          </span>
        </div>
        <SeverityBadge severity={finding.severity} />
      </div>

      <p className="mt-2 text-sm leading-relaxed text-[var(--color-ink-2)]">{finding.description}</p>

      <div className="mt-3 flex items-center gap-2 text-xs text-[var(--color-muted)]">
        <FileCode2 className="h-3.5 w-3.5 shrink-0" />
        <span className="font-mono break-all text-[var(--color-ink-2)]">{finding.file}</span>
        <span className="text-[var(--color-muted)]">:</span>
        <span className="font-mono">{finding.line}</span>
      </div>

      {finding.snippet && (
        <pre className="mt-2 overflow-x-auto rounded-lg border border-[var(--color-hairline)] bg-[var(--color-page)] p-2.5 font-mono text-xs text-[#e6a8a8]">
          {finding.snippet}
        </pre>
      )}

      <div className="mt-3 flex items-start gap-2 rounded-lg bg-[var(--color-raised)] p-2.5 text-xs text-[var(--color-ink-2)]">
        <Wrench className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--color-good)]" />
        <span><span className="font-semibold text-[var(--color-ink)]">Fix: </span>{finding.remediation}</span>
      </div>
    </div>
  );
}
