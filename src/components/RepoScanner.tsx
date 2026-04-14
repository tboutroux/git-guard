"use client";

import { useState } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Shield, ShieldAlert, ShieldCheck, AlertTriangle, Info, FileWarning,
  Clock, Files, Search, Bug, Package, ExternalLink, Sparkles, BookOpen,
} from "lucide-react";
import type { ScanSummary, Vulnerability } from "@/lib/scanner";
import type { CVEScanResult, CVEResult } from "@/lib/cve-scanner";

const SEVERITY_CONFIG = {
  critical: {
    color: "text-red-700",
    bg: "bg-red-50",
    border: "border-red-300",
    icon: ShieldAlert,
    label: "Critical",
  },
  high: {
    color: "text-orange-700",
    bg: "bg-orange-50",
    border: "border-orange-300",
    icon: AlertTriangle,
    label: "High",
  },
  medium: {
    color: "text-amber-700",
    bg: "bg-amber-50",
    border: "border-amber-300",
    icon: FileWarning,
    label: "Medium",
  },
  low: {
    color: "text-blue-700",
    bg: "bg-blue-50",
    border: "border-blue-300",
    icon: Info,
    label: "Low",
  },
  info: {
    color: "text-slate-700",
    bg: "bg-slate-100",
    border: "border-slate-300",
    icon: Info,
    label: "Info",
  },
};

function SeverityBadge({ severity }: { severity: Vulnerability["severity"] }) {
  const config = SEVERITY_CONFIG[severity];
  const Icon = config.icon;
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold ${config.bg} ${config.color} ${config.border} border`}
    >
      <Icon className="w-3 h-3" />
      {config.label}
    </span>
  );
}

function VulnerabilityCard({ vuln }: { vuln: Vulnerability }) {
  const config = SEVERITY_CONFIG[vuln.severity];
  return (
    <div
      className={`p-3 rounded-lg border bg-card shadow-sm ${config.border} ${config.bg} space-y-1.5`}
    >
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-sm text-foreground">{vuln.type}</span>
          {vuln.aiDetected && (
            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-semibold bg-purple-500/10 text-purple-400 border border-purple-500/30">
              <Sparkles className="w-3 h-3" />
              AI
            </span>
          )}
        </div>
        <SeverityBadge severity={vuln.severity} />
      </div>
      <p className="text-xs text-foreground/85">{vuln.description}</p>
      <div className="flex flex-wrap items-center gap-3 text-xs text-foreground/75">
        <span>
          📄 <span className="font-mono">{vuln.file}</span>
        </span>
        <span>Line {vuln.line}</span>
      </div>
      {vuln.match && (
        <pre className="text-xs bg-slate-900 p-2 rounded overflow-x-auto font-mono text-rose-200 border border-slate-700">
          {vuln.match}
        </pre>
      )}
    </div>
  );
}

const CVE_SEVERITY_CONFIG: Record<string, typeof SEVERITY_CONFIG["critical"]> = {
  ...SEVERITY_CONFIG,
  unknown: {
    color: "text-slate-700",
    bg: "bg-slate-100",
    border: "border-slate-300",
    icon: Info,
    label: "Unknown",
  },
};

function CVECard({ cve }: { cve: CVEResult }) {
  const config = CVE_SEVERITY_CONFIG[cve.severity] || CVE_SEVERITY_CONFIG.unknown;
  const cveId = cve.aliases.find((a) => a.startsWith("CVE-")) || cve.id;
  const allIds = [cve.id, ...cve.aliases.filter((a) => a !== cve.id)];

  return (
    <div className={`p-4 rounded-lg border bg-card shadow-sm ${config.border} ${config.bg} space-y-2`}>
      <div className="flex items-start justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <Bug className="w-4 h-4 text-foreground/70 flex-shrink-0" />
          <span className="font-bold text-sm font-mono text-foreground">{cveId}</span>
        </div>
        <span
          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold ${config.bg} ${config.color} ${config.border} border`}
        >
          {cve.severity.toUpperCase()}
        </span>
      </div>

      <p className="text-sm text-foreground/90">{cve.summary}</p>

      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="inline-flex items-center gap-1 bg-black/20 px-2 py-0.5 rounded font-mono">
          <Package className="w-3 h-3" />
          {cve.affected.package}@{cve.affected.installedVersion}
        </span>
        {cve.affected.fixedVersion && (
          <span className="inline-flex items-center gap-1 bg-green-500/10 text-green-400 px-2 py-0.5 rounded font-mono border border-green-500/30">
            Fix: {cve.affected.fixedVersion}
          </span>
        )}
        {cve.affected.vulnerableRange && (
          <span className="text-foreground/75">
            Range: {cve.affected.vulnerableRange}
          </span>
        )}
      </div>

      {allIds.length > 1 && (
        <div className="text-xs text-foreground/70">
          IDs: {allIds.join(", ")}
        </div>
      )}

      {cve.references.length > 0 && (
        <div className="flex flex-wrap gap-2 pt-1">
          {cve.references.slice(0, 3).map((url, i) => (
            <a
              key={i}
              href={url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 underline"
            >
              <ExternalLink className="w-3 h-3" />
              {url.includes("github.com") ? "GitHub Advisory" : url.includes("nvd.nist") ? "NVD" : "Reference"}
            </a>
          ))}
        </div>
      )}
    </div>
  );
}

function AIAnalysisCard({ analysis }: { analysis: string }) {
  return (
    <div className="p-4 rounded-xl border border-purple-500/30 bg-purple-500/5 space-y-3">
      <div className="flex items-center gap-2">
        <Sparkles className="w-5 h-5 text-purple-400" />
        <h3 className="font-semibold text-purple-300">AI Security Analysis</h3>
      </div>
      <div className="prose prose-sm prose-invert max-w-none text-sm leading-relaxed whitespace-pre-wrap">
        {analysis}
      </div>
    </div>
  );
}

function ScanStats({ summary }: { summary: ScanSummary }) {
  const criticalCount = summary.vulnerabilities.filter(
    (v) => v.severity === "critical"
  ).length;
  const highCount = summary.vulnerabilities.filter(
    (v) => v.severity === "high"
  ).length;
  const mediumCount = summary.vulnerabilities.filter(
    (v) => v.severity === "medium"
  ).length;
  const lowCount = summary.vulnerabilities.filter(
    (v) => v.severity === "low" || v.severity === "info"
  ).length;

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      <div className="p-3 rounded-lg bg-card border text-center">
        <Files className="w-5 h-5 mx-auto mb-1 text-muted-foreground" />
        <div className="text-lg font-bold">{summary.scannedFiles}</div>
        <div className="text-xs text-muted-foreground">Files Scanned</div>
      </div>
      <div className="p-3 rounded-lg bg-card border text-center">
        <Clock className="w-5 h-5 mx-auto mb-1 text-muted-foreground" />
        <div className="text-lg font-bold">
          {(summary.scanDuration / 1000).toFixed(1)}s
        </div>
        <div className="text-xs text-muted-foreground">Scan Duration</div>
      </div>
      <div className="p-3 rounded-lg bg-card border text-center">
        <ShieldAlert className="w-5 h-5 mx-auto mb-1 text-red-500" />
        <div className="text-lg font-bold">{criticalCount + highCount}</div>
        <div className="text-xs text-muted-foreground">Critical / High</div>
      </div>
      <div className="p-3 rounded-lg bg-card border text-center">
        <AlertTriangle className="w-5 h-5 mx-auto mb-1 text-yellow-500" />
        <div className="text-lg font-bold">{mediumCount + lowCount}</div>
        <div className="text-xs text-muted-foreground">Medium / Low</div>
      </div>
    </div>
  );
}

export default function RepoScanner() {
  const [repoUrl, setRepoUrl] = useState("");
  const [scanResult, setScanResult] = useState<ScanSummary | null>(null);
  const [cveResult, setCveResult] = useState<CVEScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingCve, setLoadingCve] = useState(false);
  const [loadingPhase, setLoadingPhase] = useState<string>("");

  const handleScan = async () => {
    if (!repoUrl.trim()) return;

    setLoading(true);
    setScanResult(null);
    setCveResult(null);
    setError(null);

    try {
      // Phase 1: Vulnerability scan + AI analysis
      setLoadingPhase("Scanning for secrets & vulnerabilities (+ AI analysis)...");
      const scanResponse = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repoUrl: repoUrl.trim() }),
      });

      const scanData = await scanResponse.json();
      if (!scanResponse.ok) {
        setError(scanData.error || "An error occurred during scanning.");
        return;
      }
      setScanResult(scanData);
    } catch {
      setError("Failed to connect to the scanning service.");
      return;
    } finally {
      setLoading(false);
      setLoadingPhase("");
    }

    // Phase 2: CVE scan (independent — results appear when ready)
    setLoadingCve(true);
    try {
      const cveResponse = await fetch("/api/cve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repoUrl: repoUrl.trim() }),
      });
      const cveData = await cveResponse.json();
      if (cveResponse.ok) {
        setCveResult(cveData);
      }
    } catch {
      // CVE scan failure is non-fatal
    } finally {
      setLoadingCve(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !loading) {
      handleScan();
    }
  };

  const hasVulnerabilities =
    scanResult && scanResult.vulnerabilities.length > 0;

  return (
    <div className="min-h-screen flex flex-col items-center p-4 md:p-8">
      {/* Header */}
      <div className="flex items-center gap-3 mb-2 mt-8">
        <Shield className="w-8 h-8 text-primary" />
        <h1 className="text-3xl font-bold">GitGuard</h1>
      </div>
      <p className="text-muted-foreground mb-8 text-center">
        Scan public GitHub repositories for security vulnerabilities and exposed secrets
      </p>

      {/* Search Card */}
      <Card className="w-full max-w-2xl p-6 rounded-2xl shadow-lg">
        <CardContent className="space-y-4">
          <label className="block text-lg font-medium">
            <Search className="w-4 h-4 inline-block mr-2" />
            Scan a Repository
          </label>
          <div className="flex gap-2">
            <Input
              type="text"
              placeholder="https://github.com/owner/repo"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              onKeyDown={handleKeyDown}
              className="flex-1 p-2 rounded-lg border border-border focus:ring focus:ring-ring"
              disabled={loading}
            />
            <Button
              onClick={handleScan}
              disabled={loading || !repoUrl.trim()}
              className="bg-primary text-primary-foreground hover:bg-primary/90 font-bold py-2 px-6 rounded-lg whitespace-nowrap"
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <span className="w-4 h-4 border-2 border-t-transparent border-white rounded-full animate-spin" />
                  Scanning...
                </span>
              ) : (
                "Scan"
              )}
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            Enter a public GitHub repository URL. The scanner checks for exposed secrets, API keys, passwords, unsafe code patterns, and known CVEs in dependencies.
          </p>
        </CardContent>
      </Card>

      {/* Error */}
      {error && (
        <div className="w-full max-w-2xl mt-6 p-4 rounded-xl border border-red-500/30 bg-red-500/10 text-red-400 flex items-start gap-3">
          <ShieldAlert className="w-5 h-5 mt-0.5 flex-shrink-0" />
          <div>
            <p className="font-semibold">Scan Failed</p>
            <p className="text-sm">{error}</p>
          </div>
        </div>
      )}

      {/* Loading state */}
      {loading && (
        <div className="w-full max-w-2xl mt-6">
          <Card className="p-6 rounded-2xl shadow-lg">
            <CardContent className="flex flex-col items-center gap-4 py-8">
              <div className="w-10 h-10 border-4 border-t-transparent border-primary rounded-full animate-spin" />
              <div className="text-center">
                <p className="font-semibold">{loadingPhase || "Scanning repository..."}</p>
                <p className="text-sm text-muted-foreground mt-1">
                  This may take a moment for large repositories.
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Results */}
      {scanResult && (
        <div className="w-full max-w-2xl mt-6 space-y-4">
          {/* Summary Header */}
          <div
            className={`p-4 rounded-xl border flex items-center gap-3 ${
              hasVulnerabilities
                ? "border-red-500/30 bg-red-500/5"
                : "border-green-500/30 bg-green-500/5"
            }`}
          >
            {hasVulnerabilities ? (
              <ShieldAlert className="w-6 h-6 text-red-500 flex-shrink-0" />
            ) : (
              <ShieldCheck className="w-6 h-6 text-green-500 flex-shrink-0" />
            )}
            <div>
              <p className="font-semibold">
                {hasVulnerabilities
                  ? `${scanResult.vulnerabilities.length} vulnerability${scanResult.vulnerabilities.length > 1 ? "ies" : "y"} found`
                  : "No vulnerabilities detected"}
              </p>
              <p className="text-sm text-muted-foreground">
                Scanned {scanResult.scannedFiles} of {scanResult.totalFiles} files
                {scanResult.aiAnalyzed && (
                  <span className="ml-2 inline-flex items-center gap-1 text-purple-400">
                    <Sparkles className="w-3 h-3" />
                    AI analysis
                  </span>
                )}
              </p>
            </div>
          </div>

          {/* Stats */}
          <ScanStats summary={scanResult} />

          {/* Vulnerability list */}
          {hasVulnerabilities && (() => {
            const aiFindings = scanResult.vulnerabilities.filter((v) => v.aiDetected);
            const regexFindings = scanResult.vulnerabilities.filter((v) => !v.aiDetected);
            return (
              <>
                {aiFindings.length > 0 && (
                  <div className="space-y-3">
                    <h2 className="text-lg font-semibold flex items-center gap-2">
                      <Sparkles className="w-5 h-5 text-purple-400" />
                      AI-Detected Findings
                      <span className="text-sm font-normal text-muted-foreground">({aiFindings.length})</span>
                    </h2>
                    {aiFindings.map((vuln, idx) => (
                      <VulnerabilityCard key={`ai-${idx}`} vuln={vuln} />
                    ))}
                  </div>
                )}
                {regexFindings.length > 0 && (
                  <div className="space-y-3">
                    <h2 className="text-lg font-semibold flex items-center gap-2">
                      <ShieldAlert className="w-5 h-5" />
                      Pattern Findings
                      <span className="text-sm font-normal text-muted-foreground">({regexFindings.length})</span>
                    </h2>
                    {regexFindings.map((vuln, idx) => (
                      <VulnerabilityCard key={`regex-${idx}`} vuln={vuln} />
                    ))}
                  </div>
                )}
              </>
            );
          })()}
        </div>
      )}

      {/* CVE loading indicator */}
      {loadingCve && (
        <div className="w-full max-w-2xl mt-4 p-3 rounded-xl border border-border flex items-center gap-3 text-sm text-muted-foreground">
          <span className="w-4 h-4 border-2 border-t-transparent border-muted-foreground rounded-full animate-spin flex-shrink-0" />
          Analyzing dependencies for known CVEs...
        </div>
      )}

      {/* CVE Results */}
      {cveResult && (
        <div className="w-full max-w-2xl mt-6 space-y-4">
          {/* CVE Summary Header */}
          <div
            className={`p-4 rounded-xl border flex items-center gap-3 ${
              cveResult.cves.length > 0
                ? "border-orange-500/30 bg-orange-500/5"
                : "border-green-500/30 bg-green-500/5"
            }`}
          >
            {cveResult.cves.length > 0 ? (
              <Bug className="w-6 h-6 text-orange-500 flex-shrink-0" />
            ) : (
              <ShieldCheck className="w-6 h-6 text-green-500 flex-shrink-0" />
            )}
            <div>
              <p className="font-semibold">
                {cveResult.cves.length > 0
                  ? `${cveResult.cves.length} known CVE${cveResult.cves.length > 1 ? "s" : ""} found`
                  : "No known CVEs in dependencies"}
              </p>
              <p className="text-sm text-muted-foreground">
                Analyzed {cveResult.dependencies.length} dependencies via OSV.dev
                {cveResult.aiAnalysis ? " • AI analysis available" : ""}
              </p>
            </div>
          </div>

          {/* Dependency Stats */}
          {cveResult.dependencies.length > 0 && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="p-3 rounded-lg bg-card border text-center">
                <Package className="w-5 h-5 mx-auto mb-1 text-muted-foreground" />
                <div className="text-lg font-bold">{cveResult.dependencies.length}</div>
                <div className="text-xs text-muted-foreground">Dependencies</div>
              </div>
              <div className="p-3 rounded-lg bg-card border text-center">
                <Bug className="w-5 h-5 mx-auto mb-1 text-red-500" />
                <div className="text-lg font-bold">{cveResult.cves.length}</div>
                <div className="text-xs text-muted-foreground">CVEs Found</div>
              </div>
              <div className="p-3 rounded-lg bg-card border text-center">
                <BookOpen className="w-5 h-5 mx-auto mb-1 text-muted-foreground" />
                <div className="text-lg font-bold">
                  {[...new Set(cveResult.dependencies.map((d) => d.ecosystem))].length}
                </div>
                <div className="text-xs text-muted-foreground">Ecosystems</div>
              </div>
              <div className="p-3 rounded-lg bg-card border text-center">
                <Clock className="w-5 h-5 mx-auto mb-1 text-muted-foreground" />
                <div className="text-lg font-bold">
                  {(cveResult.scanDuration / 1000).toFixed(1)}s
                </div>
                <div className="text-xs text-muted-foreground">CVE Scan</div>
              </div>
            </div>
          )}

          {/* AI Analysis */}
          {cveResult.aiAnalysis && (
            <AIAnalysisCard analysis={cveResult.aiAnalysis} />
          )}

          {/* CVE List */}
          {cveResult.cves.length > 0 && (
            <div className="space-y-3">
              <h2 className="text-lg font-semibold flex items-center gap-2">
                <Bug className="w-5 h-5" />
                Known CVEs
              </h2>
              {cveResult.cves.map((cve) => (
                <CVECard key={cve.id} cve={cve} />
              ))}
            </div>
          )}
        </div>
      )}

      {/* Footer */}
      <footer className="mt-auto pt-8 pb-4 text-sm text-muted-foreground">
        © 2026 GitGuard. All Rights Reserved.
      </footer>
    </div>
  );
}
