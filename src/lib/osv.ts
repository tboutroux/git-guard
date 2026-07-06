import type { CveFinding, DependencyInfo, Severity } from "./types";

// OSV.dev lookup in two steps:
//  1. /v1/querybatch — one request for the whole dependency list, returns vuln IDs
//  2. /v1/vulns/{id} — details for each unique vuln

interface OSVBatchResult {
  results: { vulns?: { id: string }[] }[];
}

interface OSVVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: { type: string; score: string }[];
  database_specific?: { severity?: string; cvss?: { score?: number } };
  affected?: {
    package?: { name: string; ecosystem: string };
    ranges?: { type: string; events: { introduced?: string; fixed?: string }[] }[];
  }[];
  references?: { type: string; url: string }[];
}

function mapSeverity(vuln: OSVVuln): CveFinding["severity"] {
  for (const s of vuln.severity ?? []) {
    // CVSS vector strings (CVSS:3.1/...) are handled via database_specific below
    const score = parseFloat(s.score);
    if (!Number.isNaN(score)) return scoreToSeverity(score);
  }
  const dbSev = vuln.database_specific?.severity?.toLowerCase();
  if (dbSev === "critical") return "critical";
  if (dbSev === "high") return "high";
  if (dbSev === "moderate" || dbSev === "medium") return "medium";
  if (dbSev === "low") return "low";
  const cvss = vuln.database_specific?.cvss?.score;
  if (typeof cvss === "number") return scoreToSeverity(cvss);
  return "unknown";
}

function scoreToSeverity(score: number): Severity {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}

export async function queryOsvBatch(deps: DependencyInfo[]): Promise<Map<string, DependencyInfo>> {
  // Map of vuln ID → the dependency that triggered it (first wins)
  const hits = new Map<string, DependencyInfo>();
  const BATCH = 100; // OSV querybatch caps at 1000 queries; stay well below

  for (let i = 0; i < deps.length; i += BATCH) {
    const slice = deps.slice(i, i + BATCH);
    try {
      const res = await fetch("https://api.osv.dev/v1/querybatch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          queries: slice.map((d) => ({
            version: d.version,
            package: { name: d.name, ecosystem: d.ecosystem },
          })),
        }),
      });
      if (!res.ok) continue;
      const data: OSVBatchResult = await res.json();
      data.results.forEach((result, idx) => {
        for (const v of result.vulns ?? []) {
          if (!hits.has(v.id)) hits.set(v.id, slice[idx]);
        }
      });
    } catch {
      // network failure on one batch is non-fatal
    }
  }
  return hits;
}

export async function fetchVulnDetails(id: string, dep: DependencyInfo): Promise<CveFinding | null> {
  try {
    const res = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`);
    if (!res.ok) return null;
    const vuln: OSVVuln = await res.json();

    const affected = vuln.affected?.find(
      (a) => a.package?.name?.toLowerCase() === dep.name.toLowerCase()
    ) ?? vuln.affected?.[0];
    const events = affected?.ranges?.[0]?.events ?? [];
    const fixed = events.find((e) => e.fixed)?.fixed ?? null;

    return {
      id: vuln.id,
      cveId: vuln.aliases?.find((a) => a.startsWith("CVE-")) ?? null,
      severity: mapSeverity(vuln),
      summary: vuln.summary || vuln.details?.slice(0, 200) || "No summary available",
      package: dep.name,
      ecosystem: dep.ecosystem,
      installedVersion: dep.version,
      fixedVersion: fixed,
      references: (vuln.references ?? []).map((r) => r.url).slice(0, 4),
    };
  } catch {
    return null;
  }
}

export async function lookupCves(
  deps: DependencyInfo[],
  onCve?: (cve: CveFinding) => void
): Promise<CveFinding[]> {
  const hits = await queryOsvBatch(deps);
  const results: CveFinding[] = [];
  const entries = [...hits.entries()];
  const CONCURRENCY = 8;

  for (let i = 0; i < entries.length; i += CONCURRENCY) {
    const slice = entries.slice(i, i + CONCURRENCY);
    const settled = await Promise.allSettled(slice.map(([id, dep]) => fetchVulnDetails(id, dep)));
    for (const result of settled) {
      if (result.status === "fulfilled" && result.value) {
        results.push(result.value);
        onCve?.(result.value);
      }
    }
  }
  return results;
}
