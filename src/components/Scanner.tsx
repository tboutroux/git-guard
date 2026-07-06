"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Shield,
  Search,
  Loader2,
  ShieldCheck,
  ShieldAlert,
  Clock,
  FileCode2,
  Package,
  Bug,
  Sparkles,
  Download,
  Star,
  History,
  Trash2,
  ExternalLink,
  RotateCw,
} from "lucide-react";
import type {
  CveFinding,
  Finding,
  PhaseId,
  Report,
  ScanEvent,
} from "@/lib/types";
import { SEVERITY_ORDER } from "@/lib/types";
import { ScanTerminal, PHASE_LABELS, type PhaseState } from "./ScanTerminal";
import { ScoreGauge } from "./ScoreGauge";
import { SeverityChart } from "./SeverityChart";
import { FindingCard } from "./FindingCard";
import { CveCard } from "./CveCard";
import { loadHistory, pushHistory, clearHistory, type HistoryEntry } from "@/lib/history";

const PHASE_ORDER: PhaseId[] = ["resolve", "clone", "secrets", "deps", "ai", "score"];

const EXAMPLES = [
  "OWASP/NodeGoat",
  "digininja/DVWA",
  "juice-shop/juice-shop",
];

function initialPhases(): PhaseState[] {
  return PHASE_ORDER.map((id) => ({ id, label: PHASE_LABELS[id], status: "pending" }));
}

type Tab = "code" | "cve";

export default function Scanner() {
  const [repoUrl, setRepoUrl] = useState("");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [phases, setPhases] = useState<PhaseState[]>(initialPhases);
  const [logs, setLogs] = useState<string[]>([]);
  const [liveFindings, setLiveFindings] = useState<Finding[]>([]);
  const [liveCves, setLiveCves] = useState<CveFinding[]>([]);
  const [progress, setProgress] = useState<{ scanned: number; total: number } | null>(null);
  const [report, setReport] = useState<Report | null>(null);

  const [tab, setTab] = useState<Tab>("code");
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [aiEnabled, setAiEnabled] = useState(true);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    setHistory(loadHistory());
    try {
      setAiEnabled(window.localStorage.getItem("GitGuard:aiEnabled") !== "off");
    } catch {
      // storage blocked — keep the default
    }
  }, []);

  const toggleAi = () => {
    setAiEnabled((prev) => {
      const next = !prev;
      try {
        window.localStorage.setItem("GitGuard:aiEnabled", next ? "on" : "off");
      } catch {
        // storage blocked — non-fatal
      }
      return next;
    });
  };

  const resetState = () => {
    setError(null);
    setPhases(initialPhases());
    setLogs([]);
    setLiveFindings([]);
    setLiveCves([]);
    setProgress(null);
    setReport(null);
  };

  const applyEvent = useCallback((event: ScanEvent) => {
    switch (event.type) {
      case "phase":
        setPhases((prev) =>
          prev.map((p) =>
            p.id === event.phase
              ? { ...p, status: event.status === "start" ? "active" : event.status === "skip" ? "skip" : "done" }
              : p
          )
        );
        break;
      case "log":
        setLogs((prev) => [...prev, event.message]);
        break;
      case "progress":
        setProgress({ scanned: event.scanned, total: event.total });
        break;
      case "finding":
        setLiveFindings((prev) => [...prev, event.finding]);
        break;
      case "cve":
        setLiveCves((prev) => [...prev, event.cve]);
        break;
      case "report":
        setReport(event.report);
        setHistory(pushHistory(event.report));
        break;
      case "error":
        setError(event.message);
        break;
    }
  }, []);

  const runScan = useCallback(
    async (url: string) => {
      const target = url.trim();
      if (!target || running) return;
      resetState();
      setRunning(true);

      const controller = new AbortController();
      abortRef.current = controller;

      try {
        const res = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ repoUrl: target, aiEnabled }),
          signal: controller.signal,
        });

        if (!res.ok) {
          const data = await res.json().catch(() => ({}));
          setError(data.error ?? "The scan request failed.");
          return;
        }
        if (!res.body) {
          setError("Streaming is not supported in this environment.");
          return;
        }

        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() ?? "";
          for (const line of lines) {
            if (!line.trim()) continue;
            try {
              applyEvent(JSON.parse(line) as ScanEvent);
            } catch {
              // partial/garbled line — ignore
            }
          }
        }
      } catch (err) {
        if ((err as Error).name !== "AbortError") {
          setError("Lost connection to the scanner.");
        }
      } finally {
        setRunning(false);
        abortRef.current = null;
      }
    },
    [running, aiEnabled, applyEvent]
  );

  const [exporting, setExporting] = useState(false);
  const downloadReport = async () => {
    if (!report || exporting) return;
    setExporting(true);
    try {
      // jsPDF is heavy — load it only when the user actually exports
      const { generatePdfReport } = await import("@/lib/report-pdf");
      generatePdfReport(report);
    } finally {
      setExporting(false);
    }
  };

  // During the run we show live-streamed items; the final report is authoritative.
  const findings = report?.findings ?? liveFindings;
  const cves = report?.cves ?? liveCves;

  const sortedFindings = useMemo(
    () => [...findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]),
    [findings]
  );
  const sortedCves = useMemo(
    () => [...cves].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]),
    [cves]
  );

  const criticalHigh = findings.filter((f) => f.severity === "critical" || f.severity === "high").length +
    cves.filter((c) => c.severity === "critical" || c.severity === "high").length;

  return (
    <div className="mx-auto w-full max-w-5xl px-4 pb-24 sm:px-6">
      {/* ── Hero ─────────────────────────────────────────── */}
      <header className="relative pt-14 pb-8 text-center sm:pt-20">
        <div className="grid-bg pointer-events-none absolute inset-x-0 -top-14 h-72" aria-hidden />
        <div className="relative">
          <div className="mb-5 inline-flex items-center gap-2.5 rounded-full border border-[var(--color-hairline)] bg-[var(--color-surface)] px-3.5 py-1.5 text-xs text-[var(--color-ink-2)]">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-[var(--color-good)] opacity-60" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-[var(--color-good)]" />
            </span>
            Static analysis · CVE detection · AI review
          </div>
          <div className="flex items-center justify-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-[var(--color-hairline-strong)] bg-[var(--color-surface)]">
              <Shield className="h-6 w-6 text-[var(--color-accent)]" />
            </div>
            <h1 className="text-4xl font-bold tracking-tight sm:text-5xl">GitGuard</h1>
          </div>
          <p className="mx-auto mt-4 max-w-xl text-[var(--color-ink-2)]">
            Point it at any public GitHub repository. GitGuard clones it, hunts for exposed
            secrets and unsafe code, cross-checks every dependency against known CVEs, and
            grades the result — live.
          </p>
        </div>
      </header>

      {/* ── Search ───────────────────────────────────────── */}
      <div className="rounded-2xl border border-[var(--color-hairline)] bg-[var(--color-surface)] p-4 shadow-2xl shadow-black/40">
        <div className="flex flex-col gap-2 sm:flex-row">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--color-muted)]" />
            <input
              type="text"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && runScan(repoUrl)}
              disabled={running}
              placeholder="https://github.com/owner/repo"
              className="w-full rounded-xl border border-[var(--color-hairline)] bg-[var(--color-page)] py-3 pl-10 pr-4 text-sm text-[var(--color-ink)] outline-none transition-colors placeholder:text-[var(--color-muted)] focus:border-[var(--color-accent)] disabled:opacity-60"
            />
          </div>
          <button
            onClick={() => runScan(repoUrl)}
            disabled={running || !repoUrl.trim()}
            className="inline-flex items-center justify-center gap-2 rounded-xl bg-[var(--color-accent)] px-6 py-3 text-sm font-semibold text-white transition-all hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {running ? (
              <><Loader2 className="h-4 w-4 animate-spin" /> Scanning…</>
            ) : (
              <><Shield className="h-4 w-4" /> Scan</>
            )}
          </button>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-[var(--color-muted)]">
          <span>Try:</span>
          {EXAMPLES.map((ex) => (
            <button
              key={ex}
              onClick={() => { setRepoUrl(ex); runScan(ex); }}
              disabled={running}
              className="rounded-md border border-[var(--color-hairline)] px-2 py-1 font-mono text-[var(--color-ink-2)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-ink)] disabled:opacity-50"
            >
              {ex}
            </button>
          ))}
          <button
            onClick={toggleAi}
            disabled={running}
            role="switch"
            aria-checked={aiEnabled}
            title={aiEnabled ? "AI code review is on — click to disable" : "AI code review is off — click to enable"}
            className="ml-auto inline-flex items-center gap-2 rounded-full border px-2.5 py-1 font-medium transition-colors disabled:opacity-50"
            style={
              aiEnabled
                ? { color: "#9085e9", borderColor: "#9085e955", backgroundColor: "#9085e915" }
                : { color: "var(--color-muted)", borderColor: "var(--color-hairline)" }
            }
          >
            <Sparkles className="h-3 w-3" />
            AI review
            <span
              className="relative inline-flex h-3.5 w-6 items-center rounded-full transition-colors"
              style={{ backgroundColor: aiEnabled ? "#9085e9" : "rgba(255,255,255,0.15)" }}
              aria-hidden
            >
              <span
                className="absolute h-2.5 w-2.5 rounded-full bg-white transition-transform"
                style={{ transform: aiEnabled ? "translateX(13px)" : "translateX(2px)" }}
              />
            </span>
          </button>
        </div>
      </div>

      {/* ── Error ────────────────────────────────────────── */}
      {error && (
        <div className="mt-5 flex items-start gap-3 rounded-xl border p-4" style={{ borderColor: "#d03b3b55", backgroundColor: "#d03b3b12" }}>
          <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-[#d03b3b]" />
          <div>
            <p className="font-semibold text-[var(--color-ink)]">Scan failed</p>
            <p className="text-sm text-[var(--color-ink-2)]">{error}</p>
          </div>
        </div>
      )}

      {/* ── Live pipeline (shown while running or after) ─── */}
      {(running || report) && (
        <section className="mt-6">
          <ScanTerminal phases={phases} logs={logs} running={running} />
          {running && progress && (
            <div className="mt-3">
              <div className="mb-1 flex justify-between text-xs text-[var(--color-muted)]">
                <span>Scanning files</span>
                <span className="tabular-nums">{progress.scanned} / {progress.total}</span>
              </div>
              <div className="h-1.5 overflow-hidden rounded-full bg-[var(--color-raised)]">
                <div
                  className="h-full rounded-full bg-[var(--color-accent)] transition-all duration-300"
                  style={{ width: `${(progress.scanned / Math.max(1, progress.total)) * 100}%` }}
                />
              </div>
            </div>
          )}
        </section>
      )}

      {/* ── Report dashboard ─────────────────────────────── */}
      {report && (
        <section className="mt-8 space-y-6">
          {/* Overview: gauge + stats */}
          <div className="grid gap-6 md:grid-cols-[auto_1fr]">
            <div className="rounded-2xl border border-[var(--color-hairline)] bg-[var(--color-surface)] p-6">
              <ScoreGauge score={report.score} />
            </div>

            <div className="flex flex-col gap-4">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <a
                    href={report.repo.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 text-lg font-semibold text-[var(--color-ink)] hover:text-[var(--color-accent)]"
                  >
                    {report.repo.owner}/{report.repo.repo}
                    <ExternalLink className="h-3.5 w-3.5" />
                  </a>
                  {report.repo.description && (
                    <p className="mt-1 max-w-md text-sm text-[var(--color-ink-2)]">{report.repo.description}</p>
                  )}
                  <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-[var(--color-muted)]">
                    {report.repo.language && <span>{report.repo.language}</span>}
                    {report.repo.stars !== null && (
                      <span className="inline-flex items-center gap-1"><Star className="h-3 w-3" /> {report.repo.stars.toLocaleString()}</span>
                    )}
                    {report.aiAnalyzed && (
                      <span className="inline-flex items-center gap-1 text-[var(--color-ai)]">
                        <Sparkles className="h-3 w-3" />
                        AI reviewed
                      </span>
                    )}
                  </div>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={downloadReport}
                    disabled={exporting}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-hairline)] px-3 py-2 text-xs font-medium text-[var(--color-ink-2)] transition-colors hover:bg-[var(--color-raised)] disabled:opacity-50"
                  >
                    {exporting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Download className="h-3.5 w-3.5" />}
                    PDF report
                  </button>
                  <button
                    onClick={() => runScan(report.repo.url)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-hairline)] px-3 py-2 text-xs font-medium text-[var(--color-ink-2)] transition-colors hover:bg-[var(--color-raised)]"
                  >
                    <RotateCw className="h-3.5 w-3.5" /> Re-scan
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <StatTile icon={FileCode2} label="Files scanned" value={report.filesScanned.toLocaleString()} />
                <StatTile icon={ShieldAlert} label="Critical / High" value={String(criticalHigh)} accent={criticalHigh > 0 ? "#ec835a" : undefined} />
                <StatTile icon={Package} label="Dependencies" value={report.dependencies.length.toLocaleString()} />
                <StatTile icon={Clock} label="Duration" value={`${(report.durationMs / 1000).toFixed(1)}s`} />
              </div>

              <SeverityChart findings={report.findings} cves={report.cves} />
            </div>
          </div>

          {/* Verdict banner */}
          <VerdictBanner report={report} />

          {/* Tabs: code findings / CVEs */}
          <div className="flex gap-1 rounded-xl border border-[var(--color-hairline)] bg-[var(--color-surface)] p-1">
            <TabButton active={tab === "code"} onClick={() => setTab("code")} icon={FileCode2} label="Code findings" count={report.findings.length} />
            <TabButton active={tab === "cve"} onClick={() => setTab("cve")} icon={Bug} label="Known CVEs" count={report.cves.length} />
          </div>

          {tab === "code" ? (
            sortedFindings.length > 0 ? (
              <div className="grid gap-3">
                {sortedFindings.map((f) => <FindingCard key={f.id} finding={f} />)}
              </div>
            ) : (
              <EmptyState icon={ShieldCheck} title="No code-level issues found" subtitle="No exposed secrets or unsafe patterns turned up in the scanned source." />
            )
          ) : (
            sortedCves.length > 0 ? (
              <div className="grid gap-3">
                {sortedCves.map((c) => <CveCard key={c.id} cve={c} />)}
              </div>
            ) : (
              <EmptyState icon={ShieldCheck} title="No known CVEs" subtitle={`All ${report.dependencies.length} analyzed dependencies are clear in the OSV.dev database.`} />
            )
          )}
        </section>
      )}

      {/* ── History (when idle) ──────────────────────────── */}
      {!running && !report && history.length > 0 && (
        <section className="mt-10">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="inline-flex items-center gap-2 text-sm font-semibold text-[var(--color-ink-2)]">
              <History className="h-4 w-4" /> Recent scans
            </h2>
            <button
              onClick={() => { clearHistory(); setHistory([]); }}
              className="inline-flex items-center gap-1 text-xs text-[var(--color-muted)] hover:text-[var(--color-ink-2)]"
            >
              <Trash2 className="h-3 w-3" /> Clear
            </button>
          </div>
          <div className="grid gap-2 sm:grid-cols-2">
            {history.map((h) => (
              <button
                key={h.slug + h.scannedAt}
                onClick={() => { setRepoUrl(h.url); runScan(h.url); }}
                className="flex items-center justify-between gap-3 rounded-xl border border-[var(--color-hairline)] bg-[var(--color-surface)] p-3 text-left transition-colors hover:border-[var(--color-hairline-strong)]"
              >
                <div className="min-w-0">
                  <div className="truncate font-mono text-sm text-[var(--color-ink)]">{h.slug}</div>
                  <div className="mt-0.5 text-xs text-[var(--color-muted)]">
                    {h.findings} findings · {h.cves} CVEs
                  </div>
                </div>
                <GradeChip score={h.score} grade={h.grade} />
              </button>
            ))}
          </div>
        </section>
      )}

      <footer className="mt-16 border-t border-[var(--color-hairline)] pt-6 text-center text-xs text-[var(--color-muted)]">
        GitGuard · pattern analysis + OSV.dev CVE data + AI code review · built for the security-scanner project
      </footer>
    </div>
  );
}

// ── Small presentational helpers ─────────────────────────────

function StatTile({
  icon: Icon,
  label,
  value,
  accent,
}: {
  icon: typeof Shield;
  label: string;
  value: string;
  accent?: string;
}) {
  return (
    <div className="rounded-xl border border-[var(--color-hairline)] bg-[var(--color-surface)] p-3">
      <Icon className="h-4 w-4 text-[var(--color-muted)]" style={accent ? { color: accent } : undefined} />
      <div className="mt-2 text-xl font-semibold text-[var(--color-ink)]" style={accent ? { color: accent } : undefined}>{value}</div>
      <div className="text-xs text-[var(--color-muted)]">{label}</div>
    </div>
  );
}

function TabButton({
  active,
  onClick,
  icon: Icon,
  label,
  count,
}: {
  active: boolean;
  onClick: () => void;
  icon: typeof Shield;
  label: string;
  count: number;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex flex-1 items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors ${
        active
          ? "bg-[var(--color-raised)] text-[var(--color-ink)]"
          : "text-[var(--color-muted)] hover:text-[var(--color-ink-2)]"
      }`}
    >
      <Icon className="h-4 w-4" />
      {label}
      <span className={`rounded-full px-1.5 text-xs tabular-nums ${active ? "bg-[var(--color-accent)]/20 text-[var(--color-accent)]" : "bg-[var(--color-hairline)]"}`}>
        {count}
      </span>
    </button>
  );
}

function EmptyState({
  icon: Icon,
  title,
  subtitle,
}: {
  icon: typeof Shield;
  title: string;
  subtitle: string;
}) {
  return (
    <div className="flex flex-col items-center gap-2 rounded-xl border border-dashed border-[var(--color-hairline-strong)] bg-[var(--color-surface)] px-6 py-10 text-center">
      <Icon className="h-8 w-8 text-[var(--color-good)]" />
      <p className="font-semibold text-[var(--color-ink)]">{title}</p>
      <p className="max-w-sm text-sm text-[var(--color-ink-2)]">{subtitle}</p>
    </div>
  );
}

function VerdictBanner({ report }: { report: Report }) {
  const clean = report.findings.length === 0 && report.cves.length === 0;
  const color = clean ? "#0ca30c" : report.score.score >= 75 ? "#fab219" : "#d03b3b";
  const Icon = clean ? ShieldCheck : ShieldAlert;
  const headline = clean
    ? "No issues detected"
    : `${report.findings.length + report.cves.length} issue${report.findings.length + report.cves.length === 1 ? "" : "s"} across ${report.filesScanned} files`;
  return (
    <div className="flex items-center gap-3 rounded-xl border p-4" style={{ borderColor: `${color}44`, backgroundColor: `${color}10` }}>
      <Icon className="h-6 w-6 shrink-0" style={{ color }} />
      <div>
        <p className="font-semibold text-[var(--color-ink)]">{headline}</p>
        <p className="text-sm text-[var(--color-ink-2)]">
          {report.score.deductions.length > 0
            ? report.score.deductions.slice(0, 3).map((d) => d.label).join(" · ")
            : "Clean bill of health from the pattern, dependency, and AI passes."}
        </p>
      </div>
    </div>
  );
}

function GradeChip({ score, grade }: { score: number; grade: string }) {
  const color = score >= 88 ? "#0ca30c" : score >= 75 ? "#fab219" : score >= 50 ? "#ec835a" : "#d03b3b";
  return (
    <span
      className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-sm font-bold"
      style={{ color, backgroundColor: `${color}1f`, border: `1px solid ${color}55` }}
    >
      {grade}
    </span>
  );
}
