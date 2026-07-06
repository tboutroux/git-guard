import Anthropic from "@anthropic-ai/sdk";
import type { Finding, Severity } from "./types";
import type { RepoFile } from "./github";

const CLAUDE_MODEL = "claude-opus-4-8";

export type AiEngine = "cloud" | "local";

export interface AiBudget {
  maxFiles: number;
  maxCharsPerFile: number;
  maxTotalChars: number;
}

// Claude has a 1M context window; the budget here is about cost & latency.
export const CLAUDE_BUDGET: AiBudget = {
  maxFiles: 12,
  maxCharsPerFile: 4_000,
  maxTotalChars: 40_000,
};

// Local models often run CPU-only at a few tokens/second — keep the prompt
// small enough that prompt-eval + generation fits well inside the timeout.
export const OLLAMA_BUDGET: AiBudget = {
  maxFiles: 3,
  maxCharsPerFile: 1_500,
  maxTotalChars: 4_500,
};

export function claudeAvailable(): boolean {
  return Boolean(process.env.ANTHROPIC_API_KEY?.trim());
}

function ollamaBaseUrl(): string {
  return (process.env.OLLAMA_API_URL?.trim() || "http://localhost:11434").replace(/\/$/, "");
}

export function ollamaModel(): string {
  return process.env.OLLAMA_MODEL?.trim() || "mistral";
}

export async function ollamaAvailable(): Promise<boolean> {
  try {
    const res = await fetch(`${ollamaBaseUrl()}/api/tags`, {
      signal: AbortSignal.timeout(2_000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

// ── File selection ─────────────────────────────────────────────
// Send the model the files most likely to contain logic-level vulnerabilities:
// routes, auth, DB access — not tests, docs, or static assets.

function fileScore(path: string, hasPatternHit: boolean): number {
  const p = "/" + path.toLowerCase();
  if (/\/(tests?|specs?|__tests?__|e2e|mocks?|fixtures?)\//.test(p)) return -1;
  if (/\.(test|spec)\.[jt]sx?$/.test(p)) return -1;
  if (/\/(docs?|examples?|samples?|assets|public|static)\//.test(p)) return -1;
  if (/\.(md|txt|json|ya?ml|toml|lock|css|scss|html)$/.test(p)) return -1;

  let score = 0;
  if (hasPatternHit) score += 5;
  if (/\/(routes?|controllers?|handlers?|api|views)\//.test(p)) score += 20;
  if (/\/(services?|middlewares?|auth|security)\//.test(p)) score += 15;
  if (/\/(models?|schemas?|entities|db|database)\//.test(p)) score += 8;
  if (/\/(lib|src|app|server|backend|core)\//.test(p)) score += 6;
  if (/(auth|login|session|password|token|jwt|oauth|user|account)/.test(p)) score += 12;
  if (/(admin|permission|role|acl|access)/.test(p)) score += 10;
  if (/(query|sql|mongo|redis|orm)/.test(p)) score += 8;
  if (/(crypto|hash|encrypt|sign|verify)/.test(p)) score += 8;
  if (/(upload|download|file|export|import|payment|checkout)/.test(p)) score += 6;
  return score;
}

export function selectFilesForAi(
  files: RepoFile[],
  patternHitPaths: Set<string>,
  budget: AiBudget = CLAUDE_BUDGET
): RepoFile[] {
  const ranked = files
    .map((f) => ({ f, score: fileScore(f.path, patternHitPaths.has(f.path)) }))
    .filter((x) => x.score > 0)
    .sort((a, b) => b.score - a.score);

  const selected: RepoFile[] = [];
  let total = 0;
  for (const { f } of ranked) {
    if (selected.length >= budget.maxFiles) break;
    const snippet = f.content.length > budget.maxCharsPerFile
      ? f.content.slice(0, budget.maxCharsPerFile) + "\n// … truncated …"
      : f.content;
    if (total + snippet.length > budget.maxTotalChars) break;
    selected.push({ path: f.path, content: snippet });
    total += snippet.length;
  }
  return selected;
}

// ── Shared prompt & schema ─────────────────────────────────────

const OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    findings: {
      type: "array",
      items: {
        type: "object",
        properties: {
          severity: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
          title: { type: "string", description: "Concise vulnerability name" },
          file: { type: "string", description: "Exact file path as given" },
          line: { type: "integer", description: "1-indexed line number of the issue" },
          snippet: { type: "string", description: "The vulnerable code, max 80 chars" },
          description: { type: "string", description: "Concrete risk and impact" },
          remediation: { type: "string", description: "Specific fix, one or two sentences" },
        },
        required: ["severity", "title", "file", "line", "snippet", "description", "remediation"],
        additionalProperties: false,
      },
    },
  },
  required: ["findings"],
  additionalProperties: false,
} as const;

const SYSTEM_PROMPT = `You are a senior application-security reviewer analyzing source files from a public repository (defensive review, authorized by the repository being public and the scan user-initiated).

Focus on issues regex scanning cannot catch: authentication/authorization logic flaws, missing or bypassable input validation, injection risks reachable from user input, insecure session or crypto usage, SSRF / open redirect / path traversal, sensitive data exposure in responses or logs, insecure deserialization, and missing security controls on sensitive endpoints.

Only report findings you are reasonably confident about, anchored to a specific file and line. Do not report style issues, secrets (a separate scanner handles those), or hypothetical problems in unreachable code. Return an empty findings array when nothing significant exists.`;

function buildUserPrompt(files: RepoFile[], repoUrl: string): string {
  const filesBlock = files
    .map((f) => `### ${f.path}\n\`\`\`\n${f.content}\n\`\`\``)
    .join("\n\n");
  return `Review these files from ${repoUrl} and report security findings:\n\n${filesBlock}`;
}

interface AiRawFinding {
  severity: Severity;
  title: string;
  file: string;
  line: number;
  snippet: string;
  description: string;
  remediation: string;
}

let counter = 0;

function toFindings(raw: AiRawFinding[] | undefined, files: RepoFile[]): Finding[] {
  const validSeverities = new Set(["critical", "high", "medium", "low", "info"]);
  const knownPaths = new Set(files.map((f) => f.path));
  return (raw ?? [])
    .filter((f) => validSeverities.has(f.severity) && knownPaths.has(f.file))
    .map((f) => ({
      id: `ai-${++counter}-${Date.now().toString(36)}`,
      severity: f.severity,
      title: f.title,
      file: f.file,
      line: Math.max(1, Math.floor(Number(f.line) || 1)),
      snippet: String(f.snippet ?? "").slice(0, 80),
      description: f.description,
      remediation: f.remediation,
      source: "ai" as const,
    }));
}

// ── Claude backend ─────────────────────────────────────────────

export async function analyzeWithClaude(files: RepoFile[], repoUrl: string): Promise<Finding[]> {
  if (files.length === 0) return [];

  const client = new Anthropic();
  const stream = client.messages.stream({
    model: CLAUDE_MODEL,
    max_tokens: 16_000,
    thinking: { type: "adaptive" },
    system: SYSTEM_PROMPT,
    output_config: { format: { type: "json_schema", schema: OUTPUT_SCHEMA } },
    messages: [{ role: "user", content: buildUserPrompt(files, repoUrl) }],
  });

  const message = await stream.finalMessage();
  if (message.stop_reason === "refusal") return [];

  const text = message.content.find((b) => b.type === "text");
  if (!text || text.type !== "text") return [];

  try {
    const parsed: { findings?: AiRawFinding[] } = JSON.parse(text.text);
    return toFindings(parsed.findings, files);
  } catch {
    return [];
  }
}

// ── Ollama backend (local fallback) ────────────────────────────
// Uses /api/chat with `format: <json schema>` so the local model's output is
// grammar-constrained to the same shape Claude produces.

export async function analyzeWithOllama(files: RepoFile[], repoUrl: string): Promise<Finding[]> {
  if (files.length === 0) return [];

  const res = await fetch(`${ollamaBaseUrl()}/api/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    signal: AbortSignal.timeout(240_000),
    body: JSON.stringify({
      model: ollamaModel(),
      stream: false,
      format: OUTPUT_SCHEMA,
      options: { temperature: 0.2, num_ctx: 4096, num_predict: 600 },
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: buildUserPrompt(files, repoUrl) },
      ],
    }),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`Ollama returned ${res.status}${body ? `: ${body.slice(0, 120)}` : ""}`);
  }

  const data = await res.json();
  const content: string = data?.message?.content ?? "";
  try {
    const parsed: { findings?: AiRawFinding[] } = JSON.parse(content);
    return toFindings(parsed.findings, files);
  } catch {
    return [];
  }
}
