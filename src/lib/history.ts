"use client";

import type { Report } from "./types";

const KEY = "GitGuard:history";
const MAX = 12;

export interface HistoryEntry {
  slug: string; // owner/repo
  url: string;
  score: number;
  grade: string;
  findings: number;
  cves: number;
  scannedAt: string;
}

export function loadHistory(): HistoryEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function pushHistory(report: Report): HistoryEntry[] {
  const entry: HistoryEntry = {
    slug: `${report.repo.owner}/${report.repo.repo}`,
    url: report.repo.url,
    score: report.score.score,
    grade: report.score.grade,
    findings: report.findings.length,
    cves: report.cves.length,
    scannedAt: report.scannedAt,
  };
  const existing = loadHistory().filter((e) => e.slug !== entry.slug);
  const next = [entry, ...existing].slice(0, MAX);
  try {
    window.localStorage.setItem(KEY, JSON.stringify(next));
  } catch {
    // storage full or blocked — non-fatal
  }
  return next;
}

export function clearHistory(): void {
  try {
    window.localStorage.removeItem(KEY);
  } catch {
    // ignore
  }
}
