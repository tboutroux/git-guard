// Shared types for the GitGuard scan pipeline.
// The API route streams ScanEvent objects as NDJSON; the UI folds them into state.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  file: string;
  line: number;
  snippet: string;
  description: string;
  remediation: string;
  source: "pattern" | "ai";
}

export interface CveFinding {
  id: string; // OSV/GHSA id
  cveId: string | null; // CVE-XXXX-XXXX alias if present
  severity: Severity | "unknown";
  summary: string;
  package: string;
  ecosystem: string;
  installedVersion: string;
  fixedVersion: string | null;
  references: string[];
}

export interface DependencyInfo {
  name: string;
  version: string;
  ecosystem: string;
  source: string;
}

export interface RepoInfo {
  owner: string;
  repo: string;
  url: string;
  description: string | null;
  defaultBranch: string;
  stars: number | null;
  language: string | null;
}

export type PhaseId = "resolve" | "clone" | "secrets" | "deps" | "ai" | "score";

export interface ScoreBreakdown {
  score: number; // 0-100
  grade: "A+" | "A" | "B" | "C" | "D" | "F";
  deductions: { label: string; points: number }[];
}

export interface Report {
  repo: RepoInfo;
  scannedAt: string;
  durationMs: number;
  filesTotal: number;
  filesScanned: number;
  findings: Finding[];
  cves: CveFinding[];
  dependencies: DependencyInfo[];
  score: ScoreBreakdown;
  aiAnalyzed: boolean;
  aiEngine: "cloud" | "local" | null;
}

export type ScanEvent =
  | { type: "phase"; phase: PhaseId; status: "start" | "done" | "skip"; detail?: string }
  | { type: "log"; message: string }
  | { type: "progress"; scanned: number; total: number }
  | { type: "finding"; finding: Finding }
  | { type: "cve"; cve: CveFinding }
  | { type: "report"; report: Report }
  | { type: "error"; message: string };

export const SEVERITY_ORDER: Record<Severity | "unknown", number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4,
  info: 5,
};
