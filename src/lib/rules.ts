import type { Severity } from "./types";

export interface PatternRule {
  title: string;
  severity: Severity;
  pattern: RegExp;
  description: string;
  remediation: string;
  /** Rules with loose patterns get placeholder filtering applied. */
  generic?: boolean;
}

export const PATTERN_RULES: PatternRule[] = [
  // ── Cloud & service credentials ─────────────────────────────
  {
    title: "AWS Access Key ID",
    severity: "critical",
    pattern: /\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g,
    description: "An AWS access key ID is committed to the repository. Anyone with this key can attempt to access the associated AWS account.",
    remediation: "Revoke the key in the AWS IAM console immediately and load credentials from environment variables or a secrets manager.",
  },
  {
    title: "AWS Secret Access Key",
    severity: "critical",
    pattern: /aws_secret(?:_access)?_key\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}["']?/gi,
    description: "An AWS secret access key appears in source. Combined with the key ID it grants full programmatic access.",
    remediation: "Rotate the credential in IAM and move it to environment configuration.",
  },
  {
    title: "GitHub Token",
    severity: "critical",
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b/g,
    description: "A GitHub personal access token is exposed. It may allow pushing code, reading private repos, or managing the account.",
    remediation: "Revoke the token at github.com/settings/tokens and use environment variables or GitHub Actions secrets.",
  },
  {
    title: "Stripe API Key",
    severity: "critical",
    pattern: /\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b/g,
    description: "A Stripe secret key is committed. Live keys allow charges, refunds, and access to customer payment data.",
    remediation: "Roll the key in the Stripe dashboard and store it server-side in environment variables only.",
  },
  {
    title: "Google API Key",
    severity: "high",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    description: "A Google API key is exposed. Depending on restrictions it may allow billable API usage on your account.",
    remediation: "Regenerate the key in Google Cloud Console and add application/IP restrictions.",
  },
  {
    title: "Slack Token",
    severity: "high",
    pattern: /\bxox[bpors]-[0-9]{10,13}-[0-9A-Za-z-]{10,}\b/g,
    description: "A Slack token is exposed, potentially allowing reading messages or posting as the workspace app.",
    remediation: "Revoke the token from the Slack app settings and rotate it.",
  },
  {
    title: "OpenAI / Anthropic API Key",
    severity: "critical",
    pattern: /\b(?:sk-proj-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,})\b/g,
    description: "An AI provider API key is committed. It allows billable API usage on your account.",
    remediation: "Revoke the key in the provider console and load it from environment variables.",
  },
  {
    title: "Private Key Material",
    severity: "critical",
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g,
    description: "A private key file is committed to the repository. Private keys must never be in source control.",
    remediation: "Remove the key from the repo and its history, then rotate the key pair.",
  },
  {
    title: "JWT Secret / Signed Token",
    severity: "high",
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    description: "A signed JWT is hardcoded. Tokens in source may grant authenticated access and reveal claims.",
    remediation: "Invalidate the token and issue tokens at runtime instead of committing them.",
  },
  {
    title: "Database Connection String",
    severity: "critical",
    pattern: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^\s"'@]+:[^\s"'@]+@[^\s"']+/gi,
    description: "A database URL with embedded username and password is committed.",
    remediation: "Change the database password and build the connection string from environment variables.",
  },

  // ── Generic secrets (placeholder-filtered) ──────────────────
  {
    title: "Hardcoded API Key",
    severity: "high",
    generic: true,
    pattern: /(?:api[_-]?key|apikey)\s*[=:]\s*["'][A-Za-z0-9_\-]{16,}["']/gi,
    description: "A value that looks like a real API key is assigned directly in source.",
    remediation: "Move the key to an environment variable and add the config file to .gitignore.",
  },
  {
    title: "Hardcoded Secret",
    severity: "high",
    generic: true,
    pattern: /(?:secret[_-]?key|client[_-]?secret|signing[_-]?key)\s*[=:]\s*["'][A-Za-z0-9_\-/+=]{12,}["']/gi,
    description: "A secret value is assigned directly in source code.",
    remediation: "Store secrets in environment variables or a dedicated secrets manager.",
  },
  {
    title: "Hardcoded Password",
    severity: "high",
    generic: true,
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*["'][^"'\s]{6,}["']/gi,
    description: "A password literal is present in source code.",
    remediation: "Never commit passwords; read them from environment configuration at runtime.",
  },
  {
    title: "Hardcoded Auth Token",
    severity: "high",
    generic: true,
    pattern: /(?:auth[_-]?token|access[_-]?token|bearer[_-]?token)\s*[=:]\s*["'][A-Za-z0-9_\-/.+=]{16,}["']/gi,
    description: "An authentication token is assigned directly in source.",
    remediation: "Issue tokens at runtime and keep them out of source control.",
  },

  // ── Unsafe code patterns ────────────────────────────────────
  {
    title: "eval() on User Input",
    severity: "high",
    pattern: /\beval\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|input|user)/gi,
    description: "eval() is called with what appears to be user-controlled input — a direct code-injection vector.",
    remediation: "Remove eval(); parse data with JSON.parse or a safe expression evaluator.",
  },
  {
    title: "SQL Injection Risk",
    severity: "high",
    pattern: /(?:execute|query|raw)\s*\(\s*[`"'](?:SELECT|INSERT|UPDATE|DELETE|DROP)[^)]*?(?:\$\{|["']\s*\+)/gi,
    description: "A SQL query is built with string interpolation or concatenation, allowing injection if any input is user-controlled.",
    remediation: "Use parameterized queries / prepared statements instead of string building.",
  },
  {
    title: "Command Injection Risk",
    severity: "high",
    pattern: /(?:exec|execSync|spawnSync?|system|popen)\s*\(\s*(?:`[^`]*\$\{|[^),]*\+\s*(?:req\.|request\.|params\.|query\.|input|user))/gi,
    description: "A shell command is built from user-controllable input, allowing arbitrary command execution.",
    remediation: "Use execFile with an argument array, or validate input against a strict allowlist.",
  },
  {
    title: "TLS Verification Disabled",
    severity: "high",
    pattern: /(?:rejectUnauthorized\s*[=:]\s*false|verify\s*[=:]\s*False|NODE_TLS_REJECT_UNAUTHORIZED[^=\n]*=\s*["']?0|InsecureSkipVerify\s*:\s*true)/g,
    description: "Certificate verification is turned off, exposing traffic to man-in-the-middle attacks.",
    remediation: "Re-enable TLS verification; for local development trust a dev CA instead.",
  },
  {
    title: "Weak Cryptographic Algorithm",
    severity: "medium",
    pattern: /(?:createHash|createCipheriv?|new MessageDigest|hashlib\.)\s*\(?\s*["'](?:md5|sha1|des|rc4|3des)["']/gi,
    description: "A broken or weak algorithm (MD5/SHA-1/DES/RC4) is used for hashing or encryption.",
    remediation: "Use SHA-256+ for hashing, bcrypt/argon2 for passwords, and AES-GCM for encryption.",
  },
  {
    title: "Insecure HTTP URL",
    severity: "low",
    pattern: /["']http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\{)[^\s"']+["']/gi,
    description: "A plain-HTTP endpoint is used; data sent to it travels unencrypted.",
    remediation: "Switch the endpoint to HTTPS.",
  },
  {
    title: "Debug Mode Enabled",
    severity: "medium",
    pattern: /\bDEBUG\s*[=:]\s*(?:True|true|["']?1["']?)\b/g,
    description: "Debug mode appears to be enabled, which can leak stack traces and internal state in production.",
    remediation: "Drive debug flags from environment configuration and default to off.",
  },
  {
    title: "Security-related TODO",
    severity: "info",
    pattern: /(?:TODO|FIXME|HACK|XXX)[:\s].{0,80}?(?:security|vuln|auth|password|secret|token|sanitiz|escap)/gi,
    description: "A comment flags unfinished security work.",
    remediation: "Track the item in your issue tracker and resolve it before release.",
  },
];
