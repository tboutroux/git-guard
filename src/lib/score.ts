import type { CveFinding, Finding, ScoreBreakdown } from "./types";

// Weighted deductions from a starting score of 100. Diminishing returns per
// category so one noisy pattern doesn't zero the score on its own.

const FINDING_WEIGHTS = { critical: 15, high: 8, medium: 4, low: 1.5, info: 0.5 };
const CVE_WEIGHTS = { critical: 12, high: 7, medium: 3, low: 1, unknown: 2, info: 0.5 };

function diminishing(count: number, weight: number, cap: number): number {
  // First hit costs full weight, each subsequent one 85% of the previous.
  let total = 0;
  let current = weight;
  for (let i = 0; i < count; i++) {
    total += current;
    current *= 0.85;
  }
  return Math.min(total, cap);
}

export function computeScore(findings: Finding[], cves: CveFinding[]): ScoreBreakdown {
  const deductions: { label: string; points: number }[] = [];

  for (const severity of ["critical", "high", "medium", "low", "info"] as const) {
    const count = findings.filter((f) => f.severity === severity).length;
    if (count === 0) continue;
    const points = diminishing(count, FINDING_WEIGHTS[severity], FINDING_WEIGHTS[severity] * 4);
    deductions.push({ label: `${count} ${severity} code finding${count > 1 ? "s" : ""}`, points });
  }

  for (const severity of ["critical", "high", "medium", "low", "unknown"] as const) {
    const count = cves.filter((c) => c.severity === severity).length;
    if (count === 0) continue;
    const points = diminishing(count, CVE_WEIGHTS[severity], CVE_WEIGHTS[severity] * 4);
    deductions.push({ label: `${count} ${severity === "unknown" ? "unrated" : severity} CVE${count > 1 ? "s" : ""}`, points });
  }

  const totalDeduction = deductions.reduce((sum, d) => sum + d.points, 0);
  const score = Math.max(0, Math.round(100 - totalDeduction));

  const grade: ScoreBreakdown["grade"] =
    score >= 97 ? "A+" :
    score >= 88 ? "A" :
    score >= 75 ? "B" :
    score >= 60 ? "C" :
    score >= 40 ? "D" : "F";

  return {
    score,
    grade,
    deductions: deductions.map((d) => ({ ...d, points: Math.round(d.points * 10) / 10 })),
  };
}
