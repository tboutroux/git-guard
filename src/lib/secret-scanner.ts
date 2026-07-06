import { PATTERN_RULES } from "./rules";
import type { Finding } from "./types";

const PLACEHOLDER_HINTS = [
  "your_", "your-", "example", "placeholder", "changeme", "change-me",
  "replace", "dummy", "sample", "insert", "xxxx", "<", ">", "...",
  "todo", "0000000000", "aaaaaaaa", "abcdef",
];

const TEMPLATE_PATH_HINTS = [".env.example", ".env.sample", ".env.template", "example", "sample", "template", "mock", "fixture"];

function extractAssignedValue(match: string): string {
  const idx = match.search(/[=:]/);
  const value = idx >= 0 ? match.slice(idx + 1) : match;
  return value.trim().replace(/^['"]|['"]$/g, "");
}

/** Shannon entropy in bits per character — real secrets are high-entropy. */
function entropy(value: string): number {
  if (!value) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function looksLikePlaceholder(value: string, filePath: string): boolean {
  const normalized = value.toLowerCase();
  if (!normalized) return true;
  if (PLACEHOLDER_HINTS.some((hint) => normalized.includes(hint))) return true;
  // In template-ish files, be stricter: also drop low-entropy values.
  const inTemplate = TEMPLATE_PATH_HINTS.some((h) => filePath.toLowerCase().includes(h));
  if (inTemplate && entropy(value) < 3.0) return true;
  // Everywhere: repeated single character or trivially short after trimming.
  if (/^(.)\1+$/.test(value)) return true;
  return false;
}

function redact(match: string): string {
  if (match.length <= 48) return match;
  return match.slice(0, 28) + "…" + match.slice(-8);
}

let counter = 0;
function nextId(): string {
  counter += 1;
  return `f-${counter.toString(36)}-${Date.now().toString(36)}`;
}

export function scanFileContent(content: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split("\n");

  for (const rule of PATTERN_RULES) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.length > 2000) continue; // skip minified blobs
      rule.pattern.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = rule.pattern.exec(line)) !== null) {
        const raw = match[0];
        if (rule.generic && looksLikePlaceholder(extractAssignedValue(raw), filePath)) continue;
        findings.push({
          id: nextId(),
          severity: rule.severity,
          title: rule.title,
          file: filePath,
          line: i + 1,
          snippet: redact(raw),
          description: rule.description,
          remediation: rule.remediation,
          source: "pattern",
        });
        if (rule.pattern.lastIndex === match.index) rule.pattern.lastIndex++;
      }
    }
  }
  return findings;
}
