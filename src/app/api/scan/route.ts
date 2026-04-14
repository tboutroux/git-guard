import { NextRequest, NextResponse } from "next/server";
import { promises as fs } from "node:fs";
import { join, relative } from "node:path";
import { tmpdir } from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import {
  scanContent,
  filterScannableFiles,
  summarizeScan,
  type Vulnerability,
} from "@/lib/scanner";
import { selectFilesForAI, analyzeWithClaude } from "@/lib/ai-scanner";

const execFileAsync = promisify(execFile);

interface GitHubTreeItem {
  path: string;
  mode: string;
  type: "blob" | "tree";
  sha: string;
  size?: number;
  url: string;
}

interface GitHubTreeResponse {
  sha: string;
  url: string;
  tree: GitHubTreeItem[];
  truncated: boolean;
}

interface GitHubBlobResponse {
  sha: string;
  size: number;
  content: string;
  encoding: string;
}

function parseGitHubUrl(url: string): { owner: string; repo: string } | null {
  const patterns = [
    /github\.com\/([^/]+)\/([^/\s#?]+)/,
    /^([^/]+)\/([^/\s]+)$/,
  ];
  for (const pattern of patterns) {
    const match = url.match(pattern);
    if (match) {
      return { owner: match[1], repo: match[2].replace(/\.git$/, "") };
    }
  }
  return null;
}

const MAX_FILE_SIZE = 500_000;
const MAX_FILES_CLONE = 5_000;   // git clone reads locally — no API cost
const MAX_FILES_API   = 200;     // each file = 1 GitHub API call — keep low

async function collectFilesRecursive(rootDir: string): Promise<string[]> {
  const files: string[] = [];
  async function walk(dir: string) {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      const relPath = relative(rootDir, fullPath).replace(/\\/g, "/");
      if (entry.isDirectory()) {
        if (
          relPath.includes(".git/") ||
          relPath.includes("node_modules/") ||
          relPath.includes("dist/") ||
          relPath.includes("build/") ||
          relPath.includes(".next/") ||
          relPath.includes("__pycache__/")
        ) continue;
        await walk(fullPath);
      } else if (entry.isFile()) {
        files.push(fullPath);
      }
    }
  }
  await walk(rootDir);
  return files;
}

function looksBinary(buf: Buffer): boolean {
  const sample = buf.subarray(0, Math.min(buf.length, 1024));
  for (const byte of sample) {
    if (byte === 0) return true;
  }
  return false;
}

// Higher score = scan first
function fileSecurityScore(path: string): number {
  // Prepend "/" so patterns like /\/(test)\// match paths starting with "test/"
  const p = "/" + path.toLowerCase();
  let score = 0;

  if (/\/(routes?|controllers?|handlers?|api)\//i.test(p))  score += 20;
  if (/\/(services?|middleware|auth|security)\//i.test(p))  score += 15;
  if (/\/(lib|src|app|server|backend)\//i.test(p))          score += 10;
  if (/\/(models?|schemas?|entities)\//i.test(p))           score += 8;

  if (/(auth|login|session|password|token|secret|jwt|oauth|user|account)/i.test(p)) score += 12;
  if (/(permission|role|admin|acl|access|privilege)/i.test(p))                      score += 10;
  if (/(database|db|query|sql|mongo|redis)/i.test(p))                               score += 8;
  if (/(crypto|hash|encrypt|sign|verify)/i.test(p))                                 score += 8;
  if (/(upload|file|download|export|import)/i.test(p))                              score += 6;
  if (/(payment|billing|order|checkout)/i.test(p))                                  score += 6;

  if (/\/(test|spec|__tests?__|e2e|fixtures?|mocks?)\//i.test(p))  score -= 15;
  if (/\.(test|spec)\.[jt]sx?$/.test(p))                           score -= 15;
  if (/\/data\/static\//i.test(p))                                  score -= 20;
  if (/\/(docs?|documentation|examples?|samples?)\//i.test(p))     score -= 10;
  if (/\.(md|txt|lock)$/.test(p))                                   score -= 10;
  if (/\/(frontend|public|assets|static|dist)\//i.test(p))         score -= 5;

  return score;
}

function prioritizeFiles<T extends { path: string }>(files: T[]): T[] {
  return [...files].sort((a, b) => fileSecurityScore(b.path) - fileSecurityScore(a.path));
}

interface ScanResult {
  vulns: Vulnerability[];
  totalFiles: number;
  scannedFiles: number;
  duration: number;
  fileContents: { path: string; content: string }[];
}

async function scanViaGitClone(
  owner: string,
  repo: string,
  startTime: number,
  token?: string
): Promise<ScanResult> {
  const tempBase = await fs.mkdtemp(join(tmpdir(), "gitguard-"));
  const repoDir = join(tempBase, "repo");

  const cloneUrl = token
    ? `https://x-access-token:${token}@github.com/${owner}/${repo}.git`
    : `https://github.com/${owner}/${repo}.git`;

  try {
    await execFileAsync("git", ["clone", "--depth", "1", cloneUrl, repoDir], {
      timeout: 120_000,
      maxBuffer: 1024 * 1024,
    });

    const allFiles = await collectFilesRecursive(repoDir);
    const relativeFiles = allFiles.map((f) => ({
      path: relative(repoDir, f).replace(/\\/g, "/"),
    }));
    const scannableFiles = filterScannableFiles(relativeFiles);
    const filesToScan = prioritizeFiles(scannableFiles).slice(0, MAX_FILES_CLONE);

    const allVulnerabilities: Vulnerability[] = [];
    const fileContents: { path: string; content: string }[] = [];

    for (const file of filesToScan) {
      try {
        const absPath = join(repoDir, file.path);
        const stat = await fs.stat(absPath);
        if (stat.size > MAX_FILE_SIZE) continue;

        const buf = await fs.readFile(absPath);
        if (looksBinary(buf)) continue;

        const content = buf.toString("utf-8");
        allVulnerabilities.push(...scanContent(content, file.path));
        fileContents.push({ path: file.path, content });
      } catch {
        // skip unreadable files
      }
    }

    return {
      vulns: allVulnerabilities,
      totalFiles: allFiles.length,
      scannedFiles: filesToScan.length,
      duration: Date.now() - startTime,
      fileContents,
    };
  } finally {
    await fs.rm(tempBase, { recursive: true, force: true }).catch(() => undefined);
  }
}

async function scanViaGitHubAPI(
  owner: string,
  repo: string,
  defaultBranch: string,
  startTime: number
): Promise<ScanResult> {
  const treeResponse = await fetchWithGitHub(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${defaultBranch}?recursive=1`
  );
  if (!treeResponse.ok) throw new Error("Failed to fetch repository tree.");

  const treeData: GitHubTreeResponse = await treeResponse.json();
  const blobFiles = treeData.tree.filter(
    (item) => item.type === "blob" && (item.size ?? 0) <= MAX_FILE_SIZE
  );

  const scannableFiles = filterScannableFiles(blobFiles.map((f) => ({ path: f.path })));
  const filesToScan = prioritizeFiles(scannableFiles).slice(0, MAX_FILES_API);

  const allVulnerabilities: Vulnerability[] = [];
  const fileContents: { path: string; content: string }[] = [];
  const BATCH_SIZE = 10;

  for (let i = 0; i < filesToScan.length; i += BATCH_SIZE) {
    const batch = filesToScan.slice(i, i + BATCH_SIZE);
    const results = await Promise.allSettled(
      batch.map(async (file: { path: string }) => {
        const blobItem = blobFiles.find((b) => b.path === file.path);
        if (!blobItem) return { vulns: [], content: null };

        const blobResponse = await fetchWithGitHub(blobItem.url);
        if (!blobResponse.ok) return { vulns: [], content: null };

        const blobData: GitHubBlobResponse = await blobResponse.json();
        const content =
          blobData.encoding === "base64"
            ? Buffer.from(blobData.content, "base64").toString("utf-8")
            : blobData.content;

        return { vulns: scanContent(content, file.path), content: { path: file.path, content } };
      })
    );

    for (const result of results) {
      if (result.status === "fulfilled") {
        allVulnerabilities.push(...result.value.vulns);
        if (result.value.content) fileContents.push(result.value.content);
      }
    }
  }

  return {
    vulns: allVulnerabilities,
    totalFiles: treeData.tree.filter((i) => i.type === "blob").length,
    scannedFiles: filesToScan.length,
    duration: Date.now() - startTime,
    fileContents,
  };
}

async function fetchWithGitHub(url: string): Promise<Response> {
  const baseHeaders: Record<string, string> = {
    Accept: "application/vnd.github.v3+json",
    "User-Agent": "GitGuard-Scanner",
  };
  const token = process.env.GITHUB_TOKEN?.trim();
  if (token) {
    const authResponse = await fetch(url, {
      headers: { ...baseHeaders, Authorization: `token ${token}` },
    });
    if (authResponse.status !== 401) return authResponse;
  }
  return fetch(url, { headers: baseHeaders });
}

async function runAIAnalysis(
  fileContents: { path: string; content: string }[],
  existingVulns: Vulnerability[],
  repoUrl: string
): Promise<{ vulns: Vulnerability[]; analyzed: boolean }> {
  if (!process.env.ANTHROPIC_API_KEY?.trim()) return { vulns: [], analyzed: false };

  const regexHitPaths = new Set(existingVulns.map((v) => v.file));
  const selected = selectFilesForAI(fileContents, regexHitPaths);
  if (selected.length === 0) return { vulns: [], analyzed: true };

  const aiVulns = await Promise.race([
    analyzeWithClaude(selected, repoUrl),
    new Promise<Vulnerability[]>((r) => setTimeout(() => r([]), 120_000)),
  ]);
  return { vulns: aiVulns, analyzed: true };
}

export async function POST(request: NextRequest) {
  const startTime = Date.now();

  try {
    const body = await request.json();
    const { repoUrl } = body;

    if (!repoUrl) {
      return NextResponse.json({ error: "Repository URL is required" }, { status: 400 });
    }

    const parsed = parseGitHubUrl(repoUrl);
    if (!parsed) {
      return NextResponse.json(
        { error: "Invalid GitHub repository URL. Use format: https://github.com/owner/repo" },
        { status: 400 }
      );
    }

    const { owner, repo } = parsed;

    const token = process.env.GITHUB_TOKEN?.trim();

    // Optional metadata check — only used to catch 401/404 early.
    // Rate-limit (403/429) and other transient errors are ignored so we can
    // proceed directly to git clone, which doesn't need the API.
    let defaultBranch = "main";
    const repoResponse = await fetchWithGitHub(`https://api.github.com/repos/${owner}/${repo}`);
    if (repoResponse.ok) {
      const repoData = await repoResponse.json();
      defaultBranch = repoData.default_branch || "main";
    } else if (repoResponse.status === 401) {
      return NextResponse.json(
        { error: "GitHub authentication failed. Check GITHUB_TOKEN or remove it to scan public repositories." },
        { status: 401 }
      );
    } else if (repoResponse.status === 404) {
      return NextResponse.json(
        { error: "Repository not found. Make sure it exists and is public." },
        { status: 404 }
      );
    }
    // 403 / 429 / other errors → fall through and let git clone attempt it

    // Primary: git clone (scans all files, no per-file API calls)
    // Fallback: GitHub API blob fetching (limited to 200 files)
    let result: ScanResult;
    try {
      result = await scanViaGitClone(owner, repo, startTime, token);
    } catch {
      result = await scanViaGitHubAPI(owner, repo, defaultBranch, startTime);
    }

    const { vulns: aiVulns, analyzed } = await runAIAnalysis(
      result.fileContents,
      result.vulns,
      repoUrl
    );

    console.log(`[SCAN] regex=${result.vulns.length} ai=${aiVulns.length} analyzed=${analyzed}`);
    console.log("[SCAN] AI vulns sample:", JSON.stringify(aiVulns.slice(0, 2)));

    return NextResponse.json(
      summarizeScan(
        [...result.vulns, ...aiVulns],
        result.totalFiles,
        result.scannedFiles,
        result.duration,
        repoUrl,
        analyzed
      )
    );
  } catch (error) {
    console.error("Scan error:", error);
    return NextResponse.json(
      { error: "An unexpected error occurred during scanning." },
      { status: 500 }
    );
  }
}
