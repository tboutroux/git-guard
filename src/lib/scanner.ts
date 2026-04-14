export interface Vulnerability {
  severity: "critical" | "high" | "medium" | "low" | "info";
  type: string;
  file: string;
  line: number;
  match: string;
  description: string;
  aiDetected?: boolean;
}

interface PatternRule {
  name: string;
  severity: Vulnerability["severity"];
  pattern: RegExp;
  description: string;
}

const SECRET_PATTERNS: PatternRule[] = [
  // API Keys & Tokens
  {
    name: "AWS Access Key",
    severity: "critical",
    pattern: /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g,
    description: "AWS Access Key ID detected. This can grant unauthorized access to AWS resources.",
  },
  {
    name: "AWS Secret Key",
    severity: "critical",
    pattern: /(?:aws_secret_access_key|aws_secret)\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}["']?/gi,
    description: "AWS Secret Access Key detected.",
  },
  {
    name: "Generic API Key",
    severity: "high",
    pattern: /(?:api[_-]?key|apikey)\s*[=:]\s*["']?[A-Za-z0-9_\-]{20,}["']?/gi,
    description: "Hardcoded API key found. API keys should be stored in environment variables.",
  },
  {
    name: "Generic Secret",
    severity: "high",
    pattern: /(?:secret|secret[_-]?key)\s*[=:]\s*["'][A-Za-z0-9_\-/+=]{10,}["']/gi,
    description: "Hardcoded secret detected. Secrets should never be committed to source control.",
  },
  {
    name: "Generic Token",
    severity: "high",
    pattern: /(?:token|auth[_-]?token|access[_-]?token)\s*[=:]\s*["'][A-Za-z0-9_\-/.+=]{10,}["']/gi,
    description: "Hardcoded token found. Tokens should be stored securely.",
  },
  {
    name: "GitHub Token",
    severity: "critical",
    pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g,
    description: "GitHub personal access token detected.",
  },
  {
    name: "Google API Key",
    severity: "high",
    pattern: /AIza[0-9A-Za-z_-]{35}/g,
    description: "Google API key detected.",
  },
  {
    name: "Slack Token",
    severity: "high",
    pattern: /xox[bpors]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g,
    description: "Slack token detected.",
  },
  {
    name: "Stripe Key",
    severity: "critical",
    pattern: /(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}/g,
    description: "Stripe API key detected. This can be used to access payment data.",
  },
  {
    name: "Private Key",
    severity: "critical",
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    description: "Private key file detected. Private keys should never be committed.",
  },

  // Passwords
  {
    name: "Hardcoded Password",
    severity: "critical",
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*["'][^"'\s]{4,}["']/gi,
    description: "Hardcoded password found. Passwords should never be in source code.",
  },
  {
    name: "Database Connection String",
    severity: "critical",
    pattern: /(?:mongodb|postgres|mysql|redis|amqp):\/\/[^\s"']+:[^\s"']+@[^\s"']+/gi,
    description: "Database connection string with credentials detected.",
  },

  // Unsafe Code Patterns
  {
    name: "Unsafe eval()",
    severity: "high",
    pattern: /\beval\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|input|user|data)/gi,
    description: "Unsafe use of eval() with user input. This can lead to code injection.",
  },
  {
    name: "SQL Injection Risk",
    severity: "high",
    pattern: /(?:execute|query|raw)\s*\(\s*[`"'](?:SELECT|INSERT|UPDATE|DELETE|DROP).*?\$\{/gi,
    description: "Potential SQL injection: string interpolation in SQL query.",
  },
  {
    name: "Command Injection Risk",
    severity: "high",
    pattern: /(?:exec|execSync|spawn|execFile)\s*\(\s*(?:`[^`]*\$\{|.*\+\s*(?:req\.|request\.|params\.|query\.|input|user))/gi,
    description: "Potential command injection: user input in shell command.",
  },
  {
    name: "Insecure HTTP",
    severity: "medium",
    pattern: /["']http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^\s"']+["']/gi,
    description: "Insecure HTTP URL detected. Use HTTPS instead.",
  },
  {
    name: "Disabled Security",
    severity: "high",
    pattern: /(?:verify\s*[=:]\s*false|rejectUnauthorized\s*[=:]\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*["']?0)/gi,
    description: "SSL/TLS verification is disabled. This makes the application vulnerable to MITM attacks.",
  },
  {
    name: "Weak Crypto",
    severity: "medium",
    pattern: /(?:createHash|createCipher)\s*\(\s*["'](?:md5|sha1|des|rc4)["']/gi,
    description: "Weak cryptographic algorithm detected. Use stronger algorithms (SHA-256+, AES).",
  },
  {
    name: "Hardcoded IP Address",
    severity: "low",
    pattern: /["']\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?["']/g,
    description: "Hardcoded IP address found. Consider using configuration or environment variables.",
  },
  {
    name: "TODO/FIXME Security",
    severity: "info",
    pattern: /(?:TODO|FIXME|HACK|XXX)\s*:?\s*.*(?:security|vuln|auth|password|secret|token|key|credential)/gi,
    description: "Security-related TODO/FIXME comment found.",
  },
];

const BINARY_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
  ".woff", ".woff2", ".ttf", ".eot", ".otf",
  ".zip", ".tar", ".gz", ".rar", ".7z",
  ".pdf", ".doc", ".docx", ".xls", ".xlsx",
  ".mp3", ".mp4", ".avi", ".mov", ".webm",
  ".exe", ".dll", ".so", ".dylib",
  ".pyc", ".class", ".o", ".obj",
  ".lock", ".sum",
]);

const GENERIC_SECRET_RULES = new Set([
  "Generic API Key",
  "Generic Secret",
  "Generic Token",
  "Hardcoded Password",
]);

const PLACEHOLDER_HINTS = [
  "your_",
  "your-",
  "example",
  "placeholder",
  "changeme",
  "change-me",
  "replace_me",
  "replace-this",
  "dummy",
  "sample",
  "test",
  "xxxx",
  "<",
  ">",
];

function extractAssignedValue(text: string): string {
  const idx = text.search(/[=:]/);
  const value = idx >= 0 ? text.slice(idx + 1) : text;
  return value.trim().replace(/^['"]|['"]$/g, "");
}

function looksLikePlaceholder(value: string): boolean {
  const normalized = value.toLowerCase().replace(/\s+/g, "");
  if (!normalized) return true;
  return PLACEHOLDER_HINTS.some((hint) => normalized.includes(hint));
}

function shouldIgnoreSecretMatch(
  rule: PatternRule,
  filePath: string,
  line: string,
  matchValue: string
): boolean {
  if (!GENERIC_SECRET_RULES.has(rule.name)) return false;

  const assignedValue = extractAssignedValue(matchValue || line);
  if (!looksLikePlaceholder(assignedValue)) return false;

  const normalizedPath = filePath.toLowerCase();
  const isTemplateFile =
    normalizedPath.includes(".env.example") ||
    normalizedPath.includes(".env.sample") ||
    normalizedPath.includes(".env.template") ||
    normalizedPath.includes("example") ||
    normalizedPath.includes("sample") ||
    normalizedPath.includes("template");

  return isTemplateFile;
}

function shouldScanFile(path: string): boolean {
  const ext = "." + path.split(".").pop()?.toLowerCase();
  if (BINARY_EXTENSIONS.has(ext)) return false;
  // Skip common non-code directories
  if (
    path.includes("node_modules/") ||
    path.includes(".git/") ||
    path.includes("vendor/") ||
    path.includes("dist/") ||
    path.includes("build/") ||
    path.includes(".next/") ||
    path.includes("__pycache__/")
  ) {
    return false;
  }
  return true;
}

export function scanContent(
  content: string,
  filePath: string
): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];
  const lines = content.split("\n");

  for (const rule of SECRET_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // Reset regex lastIndex for global patterns
      rule.pattern.lastIndex = 0;
      let match;
      while ((match = rule.pattern.exec(line)) !== null) {
        // Truncate the match for display (don't show full secrets)
        const matchStr = match[0];
        if (shouldIgnoreSecretMatch(rule, filePath, line, matchStr)) {
          continue;
        }
        const truncated =
          matchStr.length > 60
            ? matchStr.substring(0, 30) + "..." + matchStr.substring(matchStr.length - 10)
            : matchStr;

        vulnerabilities.push({
          severity: rule.severity,
          type: rule.name,
          file: filePath,
          line: i + 1,
          match: truncated,
          description: rule.description,
        });
      }
    }
  }

  return vulnerabilities;
}

export interface ScanSummary {
  totalFiles: number;
  scannedFiles: number;
  skippedFiles: number;
  vulnerabilities: Vulnerability[];
  scanDuration: number;
  repoUrl: string;
  aiAnalyzed: boolean;
}

export function filterScannableFiles(
  files: { path: string; content?: string }[]
): { path: string; content?: string }[] {
  return files.filter((f) => shouldScanFile(f.path));
}

export function summarizeScan(
  vulns: Vulnerability[],
  totalFiles: number,
  scannedFiles: number,
  duration: number,
  repoUrl: string,
  aiAnalyzed = false
): ScanSummary {
  return {
    totalFiles,
    scannedFiles,
    skippedFiles: totalFiles - scannedFiles,
    vulnerabilities: vulns.sort((a, b) => {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    }),
    scanDuration: duration,
    repoUrl,
    aiAnalyzed,
  };
}
