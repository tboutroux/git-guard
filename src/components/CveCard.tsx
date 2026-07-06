import { Bug, Package, ArrowRight, ExternalLink } from "lucide-react";
import type { CveFinding } from "@/lib/types";
import { SeverityBadge } from "./severity";

function refLabel(url: string): string {
  if (url.includes("github.com")) return "GitHub";
  if (url.includes("nvd.nist")) return "NVD";
  if (url.includes("osv.dev")) return "OSV";
  return "Ref";
}

export function CveCard({ cve }: { cve: CveFinding }) {
  return (
    <div className="rise rounded-xl border border-[var(--color-hairline)] bg-[var(--color-surface)] p-4 transition-colors hover:border-[var(--color-hairline-strong)]">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <Bug className="h-4 w-4 shrink-0 text-[var(--color-muted)]" />
          <span className="font-mono text-sm font-bold text-[var(--color-ink)]">
            {cve.cveId ?? cve.id}
          </span>
        </div>
        <SeverityBadge severity={cve.severity} />
      </div>

      <p className="mt-2 text-sm leading-relaxed text-[var(--color-ink-2)]">{cve.summary}</p>

      <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
        <span className="inline-flex items-center gap-1.5 rounded-md bg-[var(--color-raised)] px-2 py-1 font-mono text-[var(--color-ink-2)]">
          <Package className="h-3 w-3" />
          {cve.package}@{cve.installedVersion}
        </span>
        {cve.fixedVersion && (
          <span className="inline-flex items-center gap-1 rounded-md px-2 py-1 font-mono text-[var(--color-good)]" style={{ backgroundColor: "#0ca30c1a", border: "1px solid #0ca30c44" }}>
            <ArrowRight className="h-3 w-3" />
            {cve.fixedVersion}
          </span>
        )}
      </div>

      {cve.references.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-3">
          {cve.references.map((url) => (
            <a
              key={url}
              href={url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-xs text-[var(--color-accent)] underline-offset-2 hover:underline"
            >
              <ExternalLink className="h-3 w-3" />
              {refLabel(url)}
            </a>
          ))}
        </div>
      )}
    </div>
  );
}
