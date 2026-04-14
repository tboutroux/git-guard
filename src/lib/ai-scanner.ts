import Anthropic from "@anthropic-ai/sdk";
import type { Vulnerability } from "./scanner";

const MAX_FILES_FOR_AI = 15;
const MAX_CHARS_PER_FILE = 4_000;
const MAX_TOTAL_CHARS = 48_000;

// Returns a score for how security-relevant a file is for AI analysis.
// Higher = more important to send. Mirrors the logic in scan/route.ts.
function aiFileScore(path: string, isRegexHit: boolean): number {
  // Prepend "/" so patterns like /\/(test)\// match paths starting with "test/"
  const p = "/" + path.toLowerCase();
  let score = 0;

  // Hard exclude: test/spec files
  if (/\/(test|spec|__tests?__|e2e|mocks?|fixtures?)\//i.test(p)) return -1000;
  if (/\.(test|spec)\.[jt]sx?$/.test(p)) return -1000;

  // Hard exclude: static data, docs, challenge examples, frontend
  if (/\/data\/static\//i.test(p)) return -1000;
  if (/\/(docs?|documentation|examples?|samples?)\//i.test(p)) return -1000;
  if (/(codeFix|hacking-instructor)/i.test(p)) return -1000;
  if (/\/(frontend|public|assets|components|views|pages)\//i.test(p)) return -1000;

  // Bonus for regex hits (but not overwhelming)
  if (isRegexHit) score += 5;

  // Source directories — the actual application code
  if (/\/(routes?|controllers?|handlers?)\//i.test(p)) score += 20;
  if (/\/(services?|middleware|auth|security)\//i.test(p)) score += 15;
  if (/\/(lib|src|server|backend)\//i.test(p)) score += 10;
  if (/\/(models?|schemas?|entities)\//i.test(p)) score += 8;

  // Security-relevant filenames
  if (/(auth|login|session|password|token|jwt|oauth)/i.test(p)) score += 12;
  if (/(permission|role|admin|acl|access|privilege)/i.test(p)) score += 10;
  if (/(database|db|query|sql|mongo|redis)/i.test(p)) score += 8;
  if (/(crypto|hash|encrypt|sign|verify)/i.test(p)) score += 8;
  if (/(upload|file|download|export|payment)/i.test(p)) score += 6;

  return score;
}

export function selectFilesForAI(
  allFiles: { path: string; content: string }[],
  regexHitPaths: Set<string>
): { path: string; content: string }[] {
  const scored = allFiles
    .map((f) => ({ file: f, score: aiFileScore(f.path, regexHitPaths.has(f.path)) }))
    .filter(({ score }) => score > -1000)
    .sort((a, b) => b.score - a.score);

  const selected: { path: string; content: string }[] = [];
  let totalChars = 0;

  for (const { file } of scored) {
    if (selected.length >= MAX_FILES_FOR_AI) break;
    const snippet =
      file.content.length > MAX_CHARS_PER_FILE
        ? file.content.slice(0, MAX_CHARS_PER_FILE) + "\n// ... (truncated)"
        : file.content;
    if (totalChars + snippet.length > MAX_TOTAL_CHARS) break;
    selected.push({ path: file.path, content: snippet });
    totalChars += snippet.length;
  }

  return selected;
}

export async function analyzeWithClaude(
  files: { path: string; content: string }[],
  repoUrl: string
): Promise<Vulnerability[]> {
  if (files.length === 0) return [];

  const apiKey = process.env.ANTHROPIC_API_KEY?.trim();
  if (!apiKey) return [];

  const client = new Anthropic({ apiKey });

  const filesBlock = files
    .map((f) => `### ${f.path}\n\`\`\`\n${f.content}\n\`\`\``)
    .join("\n\n");

  const systemPrompt = `You are an expert security code reviewer. Analyze code files for security vulnerabilities with deep contextual understanding — not just pattern matching.

Respond ONLY with a valid JSON array. No prose, no markdown fences around the array. Each object in the array:
{
  "severity": "critical" | "high" | "medium" | "low" | "info",
  "type": "Concise vulnerability name",
  "file": "exact/file/path",
  "line": <integer line number>,
  "match": "relevant code snippet ≤80 chars",
  "description": "Concrete explanation of the risk and impact",
  "aiDetected": true
}

Focus on issues that regex pattern matching cannot reliably catch:
- Authentication and authorization logic flaws
- Missing or bypassable input validation
- Business logic vulnerabilities
- Insecure session management
- Sensitive data exposure in responses or logs
- Insecure cryptographic usage or key derivation
- Injection risks (SQL, command, LDAP, XPath, template)
- SSRF, open redirect, path traversal
- Race conditions in security-critical code
- Missing rate limiting on sensitive endpoints
- Overly permissive CORS or security headers
- Prototype pollution and insecure deserialization

Return [] if no significant issues are found.`;

  console.log(`[AI] Analyzing ${files.length} files:`, files.map((f) => f.path));

  try {
    const stream = client.messages.stream({
      model: "claude-sonnet-4-6",
      max_tokens: 4_000,
      system: systemPrompt,
      messages: [
        {
          role: "user",
          content: `Analyze these files from ${repoUrl}:\n\n${filesBlock}`,
        },
      ],
    });

    const message = await stream.finalMessage();

    console.log("[AI] Response blocks:", message.content.map((b) => b.type));

    const textBlock = message.content.find((b) => b.type === "text");
    if (!textBlock || textBlock.type !== "text") {
      console.log("[AI] No text block in response — full content:", JSON.stringify(message.content).slice(0, 500));
      return [];
    }

    const raw = textBlock.text.trim();
    console.log("[AI] Raw response (first 500 chars):", raw.slice(0, 500));

    const jsonStart = raw.indexOf("[");
    const jsonEnd = raw.lastIndexOf("]");
    if (jsonStart === -1 || jsonEnd === -1) {
      console.log("[AI] No JSON array found in response");
      return [];
    }

    const findings = JSON.parse(raw.slice(jsonStart, jsonEnd + 1)) as Array<{
      severity: Vulnerability["severity"];
      type: string;
      file: string;
      line: number;
      match: string;
      description: string;
      aiDetected: boolean;
    }>;

    console.log(`[AI] Parsed ${findings.length} raw findings`);

    const validSeverities = new Set(["critical", "high", "medium", "low", "info"]);
    const valid = findings.filter(
      (f) =>
        validSeverities.has(f.severity) &&
        typeof f.type === "string" &&
        typeof f.file === "string" &&
        typeof f.line === "number" &&
        typeof f.description === "string"
    );

    console.log(`[AI] ${valid.length} findings passed validation`);

    return valid.map((f) => ({
      severity: f.severity,
      type: f.type,
      file: f.file,
      line: Math.max(1, Math.floor(f.line)),
      match: typeof f.match === "string" ? f.match.slice(0, 80) : "",
      description: f.description,
      aiDetected: true as const,
    }));
  } catch (err) {
    console.log("[AI] Parse error:", err);
    return [];
  }
}
