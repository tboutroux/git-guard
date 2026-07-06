import { NextRequest, NextResponse } from "next/server";
import { parseGitHubUrl, fetchRepoInfo, cloneRepo, collectFiles, RepoNotFoundError } from "@/lib/github";
import { scanFileContent } from "@/lib/secret-scanner";
import { isDependencyFile, parseDependencies, dedupeDependencies } from "@/lib/dependencies";
import { lookupCves } from "@/lib/osv";
import {
  claudeAvailable,
  ollamaAvailable,
  selectFilesForAi,
  analyzeWithClaude,
  analyzeWithOllama,
  CLAUDE_BUDGET,
  OLLAMA_BUDGET,
  type AiEngine,
} from "@/lib/ai";
import { computeScore } from "@/lib/score";
import type { CveFinding, Finding, Report, ScanEvent } from "@/lib/types";

export const runtime = "nodejs";
export const maxDuration = 300;

export async function POST(request: NextRequest) {
  let repoUrl: string;
  let aiEnabled = true;
  try {
    const body = await request.json();
    repoUrl = String(body.repoUrl ?? "");
    aiEnabled = body.aiEnabled !== false;
  } catch {
    return NextResponse.json({ error: "Invalid request body" }, { status: 400 });
  }

  const parsed = parseGitHubUrl(repoUrl);
  if (!parsed) {
    return NextResponse.json(
      { error: "Invalid GitHub URL — use https://github.com/owner/repo" },
      { status: 400 }
    );
  }

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      let closed = false;
      const emit = (event: ScanEvent) => {
        if (closed) return;
        try {
          controller.enqueue(encoder.encode(JSON.stringify(event) + "\n"));
        } catch {
          closed = true;
        }
      };

      const startedAt = Date.now();
      const { owner, repo } = parsed;
      let cleanup: (() => Promise<void>) | null = null;

      try {
        // ── Phase 1: resolve repository ────────────────────────
        emit({ type: "phase", phase: "resolve", status: "start" });
        emit({ type: "log", message: `Resolving github.com/${owner}/${repo} …` });
        const repoInfo = await fetchRepoInfo(owner, repo);
        emit({
          type: "log",
          message: `Found ${owner}/${repo}` +
            (repoInfo.language ? ` · ${repoInfo.language}` : "") +
            (repoInfo.stars !== null ? ` · ★ ${repoInfo.stars.toLocaleString()}` : ""),
        });
        emit({ type: "phase", phase: "resolve", status: "done" });

        // ── Phase 2: clone + collect files ─────────────────────
        emit({ type: "phase", phase: "clone", status: "start" });
        emit({ type: "log", message: `git clone --depth 1 (branch: ${repoInfo.defaultBranch})` });
        const cloned = await cloneRepo(owner, repo);
        cleanup = cloned.cleanup;
        const { files, total } = await collectFiles(cloned.dir);
        emit({ type: "log", message: `Collected ${files.length} scannable text files (${total} total)` });
        emit({ type: "phase", phase: "clone", status: "done" });

        // ── Phase 3: secret & pattern scan ─────────────────────
        emit({ type: "phase", phase: "secrets", status: "start" });
        emit({ type: "log", message: "Running secret & unsafe-pattern analysis …" });
        const patternFindings: Finding[] = [];
        for (let i = 0; i < files.length; i++) {
          const fileFindings = scanFileContent(files[i].content, files[i].path);
          for (const finding of fileFindings) {
            patternFindings.push(finding);
            emit({ type: "finding", finding });
          }
          if (i % 50 === 0 || i === files.length - 1) {
            emit({ type: "progress", scanned: i + 1, total: files.length });
            // yield to the event loop so progress actually flushes
            await new Promise((r) => setTimeout(r, 0));
          }
        }
        emit({ type: "log", message: `Pattern scan complete — ${patternFindings.length} finding${patternFindings.length === 1 ? "" : "s"}` });
        emit({ type: "phase", phase: "secrets", status: "done" });

        // ── Phases 4 & 5 in parallel: CVE lookup + AI review ───
        const depFiles = files.filter((f) => isDependencyFile(f.path));
        const dependencies = dedupeDependencies(
          depFiles.flatMap((f) => parseDependencies(f.path, f.content))
        );

        const cvePromise = (async (): Promise<CveFinding[]> => {
          emit({ type: "phase", phase: "deps", status: "start" });
          if (dependencies.length === 0) {
            emit({ type: "log", message: "No dependency manifests found — skipping CVE lookup" });
            emit({ type: "phase", phase: "deps", status: "skip" });
            return [];
          }
          emit({
            type: "log",
            message: `Parsed ${dependencies.length} dependencies from ${depFiles.length} manifest${depFiles.length === 1 ? "" : "s"} — querying OSV.dev`,
          });
          const cves = await lookupCves(dependencies, (cve) => emit({ type: "cve", cve }));
          emit({ type: "log", message: `OSV.dev returned ${cves.length} known vulnerabilit${cves.length === 1 ? "y" : "ies"}` });
          emit({ type: "phase", phase: "deps", status: "done" });
          return cves;
        })();

        const aiPromise = (async (): Promise<{ findings: Finding[]; engine: AiEngine | null }> => {
          emit({ type: "phase", phase: "ai", status: "start" });
          if (!aiEnabled) {
            emit({ type: "log", message: "AI review disabled for this scan" });
            emit({ type: "phase", phase: "ai", status: "skip" });
            return { findings: [], engine: null };
          }
          const hitPaths = new Set(patternFindings.map((f) => f.file));

          const hasClaude = claudeAvailable();
          const hasOllama = await ollamaAvailable();
          if (!hasClaude && !hasOllama) {
            emit({ type: "log", message: "AI engine not configured — skipping AI review" });
            emit({ type: "phase", phase: "ai", status: "skip" });
            return { findings: [], engine: null };
          }

          const finish = (findings: Finding[], engine: AiEngine) => {
            for (const finding of findings) emit({ type: "finding", finding });
            emit({ type: "log", message: `AI review complete — ${findings.length} contextual finding${findings.length === 1 ? "" : "s"}` });
            emit({ type: "phase", phase: "ai", status: "done" });
            return { findings, engine };
          };

          // Preferred backend: hosted engine (deeper review, bigger context)
          if (hasClaude) {
            const selected = selectFilesForAi(files, hitPaths, CLAUDE_BUDGET);
            if (selected.length === 0) {
              emit({ type: "log", message: "No security-relevant source files for AI review" });
              emit({ type: "phase", phase: "ai", status: "skip" });
              return { findings: [], engine: null };
            }
            emit({ type: "log", message: `AI engine analyzing ${selected.length} high-signal files …` });
            try {
              return finish(await analyzeWithClaude(selected, repoInfo.url), "cloud");
            } catch (err) {
              console.error("[ai] primary engine error:", err);
              emit({
                type: "log",
                message: `Primary AI engine unavailable${hasOllama ? " — switching to local inference" : ""}`,
              });
            }
          }

          // Fallback backend: local inference
          if (hasOllama) {
            const selected = selectFilesForAi(files, hitPaths, OLLAMA_BUDGET);
            if (selected.length === 0) {
              emit({ type: "log", message: "No security-relevant source files for AI review" });
              emit({ type: "phase", phase: "ai", status: "skip" });
              return { findings: [], engine: null };
            }
            emit({ type: "log", message: `Local AI engine analyzing ${selected.length} files — this can take a few minutes …` });
            try {
              return finish(await analyzeWithOllama(selected, repoInfo.url), "local");
            } catch (err) {
              console.error("[ai] local engine error:", err);
              emit({ type: "log", message: "Local AI engine failed — continuing without AI review" });
            }
          }

          emit({ type: "phase", phase: "ai", status: "skip" });
          return { findings: [], engine: null };
        })();

        const [cves, ai] = await Promise.all([cvePromise, aiPromise]);

        // ── Phase 6: score + report ────────────────────────────
        emit({ type: "phase", phase: "score", status: "start" });
        const allFindings = [...patternFindings, ...ai.findings];
        const score = computeScore(allFindings, cves);
        emit({ type: "log", message: `Security score: ${score.score}/100 (grade ${score.grade})` });

        const report: Report = {
          repo: repoInfo,
          scannedAt: new Date().toISOString(),
          durationMs: Date.now() - startedAt,
          filesTotal: total,
          filesScanned: files.length,
          findings: allFindings,
          cves,
          dependencies,
          score,
          aiAnalyzed: ai.engine !== null,
          aiEngine: ai.engine,
        };
        emit({ type: "phase", phase: "score", status: "done" });
        emit({ type: "report", report });
      } catch (err) {
        const message =
          err instanceof RepoNotFoundError
            ? err.message
            : err instanceof Error
              ? err.message
              : "An unexpected error occurred during the scan.";
        emit({ type: "error", message });
      } finally {
        await cleanup?.();
        if (!closed) {
          try {
            controller.close();
          } catch {
            // already closed by the client
          }
        }
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "application/x-ndjson; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      "X-Accel-Buffering": "no",
    },
  });
}
