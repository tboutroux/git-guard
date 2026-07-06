import { promises as fs } from "node:fs";
import { join, relative } from "node:path";
import { tmpdir } from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { RepoInfo } from "./types";

const execFileAsync = promisify(execFile);

const NAME_RE = /^[A-Za-z0-9_.-]+$/;

export function parseGitHubUrl(input: string): { owner: string; repo: string } | null {
  const trimmed = input.trim();
  const patterns = [
    /github\.com[/:]([^/\s]+)\/([^/\s#?]+)/,
    /^([^/\s]+)\/([^/\s]+)$/,
  ];
  for (const pattern of patterns) {
    const match = trimmed.match(pattern);
    if (match) {
      const owner = match[1];
      const repo = match[2].replace(/\.git$/, "");
      if (NAME_RE.test(owner) && NAME_RE.test(repo)) return { owner, repo };
    }
  }
  return null;
}

export async function fetchRepoInfo(owner: string, repo: string): Promise<RepoInfo> {
  const fallback: RepoInfo = {
    owner,
    repo,
    url: `https://github.com/${owner}/${repo}`,
    description: null,
    defaultBranch: "main",
    stars: null,
    language: null,
  };

  const headers: Record<string, string> = {
    Accept: "application/vnd.github.v3+json",
    "User-Agent": "GitGuard-Scanner",
  };
  const token = process.env.GITHUB_TOKEN?.trim();
  if (token) headers.Authorization = `token ${token}`;

  try {
    const res = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers });
    if (res.status === 404) throw new RepoNotFoundError();
    if (!res.ok) return fallback;
    const data = await res.json();
    return {
      ...fallback,
      description: data.description ?? null,
      defaultBranch: data.default_branch ?? "main",
      stars: typeof data.stargazers_count === "number" ? data.stargazers_count : null,
      language: data.language ?? null,
    };
  } catch (err) {
    if (err instanceof RepoNotFoundError) throw err;
    return fallback; // metadata is nice-to-have; the clone is authoritative
  }
}

export class RepoNotFoundError extends Error {
  constructor() {
    super("Repository not found — make sure it exists and is public.");
  }
}

export interface ClonedRepo {
  dir: string;
  cleanup: () => Promise<void>;
}

export async function cloneRepo(owner: string, repo: string): Promise<ClonedRepo> {
  const tempBase = await fs.mkdtemp(join(tmpdir(), "GitGuard-"));
  const dir = join(tempBase, "repo");
  const token = process.env.GITHUB_TOKEN?.trim();
  const cloneUrl = token
    ? `https://x-access-token:${token}@github.com/${owner}/${repo}.git`
    : `https://github.com/${owner}/${repo}.git`;

  try {
    await execFileAsync("git", ["clone", "--depth", "1", "--", cloneUrl, dir], {
      timeout: 120_000,
      maxBuffer: 4 * 1024 * 1024,
    });
  } catch (err) {
    await fs.rm(tempBase, { recursive: true, force: true }).catch(() => undefined);
    throw new Error(
      `git clone failed for ${owner}/${repo} — check that the repository is public and reachable.`,
      { cause: err }
    );
  }

  return {
    dir,
    cleanup: () => fs.rm(tempBase, { recursive: true, force: true }).catch(() => undefined),
  };
}

const SKIP_DIRS = new Set([
  ".git", "node_modules", "vendor", "dist", "build", "out", ".next",
  "__pycache__", ".venv", "venv", "target", "coverage", ".cache",
]);

const BINARY_EXTENSIONS = new Set([
  "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "webp", "avif",
  "woff", "woff2", "ttf", "eot", "otf",
  "zip", "tar", "gz", "rar", "7z", "jar", "war",
  "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
  "mp3", "mp4", "avi", "mov", "webm", "ogg", "wav",
  "exe", "dll", "so", "dylib", "bin", "wasm",
  "pyc", "class", "o", "obj", "a",
  "min.js", "min.css", "map",
]);

const MAX_FILE_SIZE = 500_000;

export interface RepoFile {
  path: string; // repo-relative, forward slashes
  content: string;
}

function isBinaryPath(path: string): boolean {
  const lower = path.toLowerCase();
  if (lower.endsWith(".min.js") || lower.endsWith(".min.css")) return true;
  const ext = lower.split(".").pop() ?? "";
  return BINARY_EXTENSIONS.has(ext);
}

function looksBinary(buf: Buffer): boolean {
  const sample = buf.subarray(0, Math.min(buf.length, 1024));
  return sample.includes(0);
}

/** Walk the clone and return readable text files, plus the total file count. */
export async function collectFiles(rootDir: string): Promise<{ files: RepoFile[]; total: number }> {
  const paths: string[] = [];
  async function walk(dir: string) {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        await walk(join(dir, entry.name));
      } else if (entry.isFile()) {
        paths.push(join(dir, entry.name));
      }
    }
  }
  await walk(rootDir);

  const files: RepoFile[] = [];
  for (const absPath of paths) {
    const relPath = relative(rootDir, absPath).replace(/\\/g, "/");
    if (isBinaryPath(relPath)) continue;
    try {
      const stat = await fs.stat(absPath);
      if (stat.size > MAX_FILE_SIZE) continue;
      const buf = await fs.readFile(absPath);
      if (looksBinary(buf)) continue;
      files.push({ path: relPath, content: buf.toString("utf-8") });
    } catch {
      // unreadable file — skip
    }
  }
  return { files, total: paths.length };
}
