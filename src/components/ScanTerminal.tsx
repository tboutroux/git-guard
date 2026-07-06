"use client";

import { useEffect, useRef } from "react";
import { Check, Loader2, Minus, type LucideIcon } from "lucide-react";
import type { PhaseId } from "@/lib/types";

export interface PhaseState {
  id: PhaseId;
  label: string;
  status: "pending" | "active" | "done" | "skip";
}

export const PHASE_LABELS: Record<PhaseId, string> = {
  resolve: "Resolve repository",
  clone: "Clone & index files",
  secrets: "Secret & pattern scan",
  deps: "Dependency CVE lookup",
  ai: "AI code review",
  score: "Compute security score",
};

function StatusIcon({ status }: { status: PhaseState["status"] }) {
  if (status === "done")
    return <Check className="h-3.5 w-3.5 text-[var(--color-good)]" />;
  if (status === "active")
    return <Loader2 className="h-3.5 w-3.5 animate-spin text-[var(--color-accent)]" />;
  if (status === "skip")
    return <Minus className="h-3.5 w-3.5 text-[var(--color-muted)]" />;
  const Dot: LucideIcon = Minus;
  return <Dot className="h-3.5 w-3.5 text-[var(--color-hairline-strong)] opacity-40" />;
}

export function ScanTerminal({
  phases,
  logs,
  running,
}: {
  phases: PhaseState[];
  logs: string[];
  running: boolean;
}) {
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
  }, [logs]);

  return (
    <div className="grid gap-4 md:grid-cols-[minmax(0,260px)_1fr]">
      {/* Phase checklist */}
      <div className="rounded-xl border border-[var(--color-hairline)] bg-[var(--color-surface)] p-4">
        <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-[var(--color-muted)]">
          Pipeline
        </div>
        <ol className="flex flex-col gap-2.5">
          {phases.map((phase) => (
            <li key={phase.id} className="flex items-center gap-2.5 text-sm">
              <span className="flex h-5 w-5 shrink-0 items-center justify-center">
                <StatusIcon status={phase.status} />
              </span>
              <span
                className={
                  phase.status === "pending"
                    ? "text-[var(--color-muted)]"
                    : phase.status === "skip"
                      ? "text-[var(--color-muted)] line-through decoration-[var(--color-hairline-strong)]"
                      : "text-[var(--color-ink-2)]"
                }
              >
                {phase.label}
              </span>
            </li>
          ))}
        </ol>
      </div>

      {/* Live log */}
      <div
        className={`rounded-xl border border-[var(--color-hairline)] bg-[var(--color-page)] ${running ? "scan-sweep" : ""}`}
      >
        <div className="flex items-center gap-1.5 border-b border-[var(--color-hairline)] px-4 py-2.5">
          <span className="h-2.5 w-2.5 rounded-full bg-[#d03b3b]/70" />
          <span className="h-2.5 w-2.5 rounded-full bg-[#fab219]/70" />
          <span className="h-2.5 w-2.5 rounded-full bg-[#0ca30c]/70" />
          <span className="ml-2 font-mono text-xs text-[var(--color-muted)]">GitGuard — scan log</span>
        </div>
        <div
          ref={logRef}
          className="terminal-scroll h-[220px] overflow-y-auto p-4 font-mono text-xs leading-relaxed"
        >
          {logs.map((line, i) => (
            <div key={i} className="flex gap-2 text-[var(--color-ink-2)]">
              <span className="shrink-0 select-none text-[var(--color-accent)]">›</span>
              <span className="break-all">{line}</span>
            </div>
          ))}
          {running && (
            <div className="flex gap-2 text-[var(--color-muted)]">
              <span className="shrink-0 select-none text-[var(--color-accent)]">›</span>
              <span className="cursor-blink" />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
