import { NextRequest, NextResponse } from "next/server";
import {
  isDependencyFile,
  parseDependencyFile,
  queryAllDependencies,
  generateAIAnalysis,
  type Dependency,
  type CVEScanResult,
} from "@/lib/cve-scanner";

interface GitHubTreeItem {
  path: string;
  type: "blob" | "tree";
  sha: string;
  size?: number;
  url: string;
}

interface GitHubTreeResponse {
  tree: GitHubTreeItem[];
}

interface GitHubBlobResponse {
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

async function fetchWithGitHub(url: string): Promise<Response> {
  const baseHeaders: Record<string, string> = {
    Accept: "application/vnd.github.v3+json",
    "User-Agent": "GitGuard-Scanner",
  };

  const token = process.env.GITHUB_TOKEN?.trim();
  if (token) {
    const authResponse = await fetch(url, {
      headers: {
        ...baseHeaders,
        Authorization: `token ${token}`,
      },
    });

    if (authResponse.status !== 401) {
      return authResponse;
    }
  }

  return fetch(url, { headers: baseHeaders });
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
        { error: "Invalid GitHub repository URL." },
        { status: 400 }
      );
    }

    const { owner, repo } = parsed;

    // 1. Get default branch
    const repoResponse = await fetchWithGitHub(
      `https://api.github.com/repos/${owner}/${repo}`
    );
    if (!repoResponse.ok) {
      if (repoResponse.status === 401) {
        return NextResponse.json(
          { error: "GitHub authentication failed. Check GITHUB_TOKEN or remove it to scan public repositories." },
          { status: 401 }
        );
      }
      if (repoResponse.status === 404) {
        return NextResponse.json({ error: "Repository not found." }, { status: 404 });
      }
      if (repoResponse.status === 403) {
        return NextResponse.json(
          { error: "GitHub API rate limit exceeded. Try again later or set a GITHUB_TOKEN." },
          { status: 429 }
        );
      }
      return NextResponse.json({ error: `GitHub API error: ${repoResponse.statusText}` }, { status: repoResponse.status });
    }

    const repoData = await repoResponse.json();
    const defaultBranch = repoData.default_branch || "main";

    // 2. Get file tree
    const treeResponse = await fetchWithGitHub(
      `https://api.github.com/repos/${owner}/${repo}/git/trees/${defaultBranch}?recursive=1`
    );
    if (!treeResponse.ok) {
      return NextResponse.json({ error: "Failed to fetch repository tree." }, { status: 500 });
    }

    const treeData: GitHubTreeResponse = await treeResponse.json();

    // 3. Find dependency files
    const depFiles = treeData.tree.filter(
      (item) => item.type === "blob" && isDependencyFile(item.path)
    );

    if (depFiles.length === 0) {
      const duration = Date.now() - startTime;
      const result: CVEScanResult = {
        dependencies: [],
        cves: [],
        aiAnalysis: null,
        scanDuration: duration,
      };
      return NextResponse.json(result);
    }

    // 4. Fetch and parse dependency files
    const allDeps: Dependency[] = [];

    const depResults = await Promise.allSettled(
      depFiles.map(async (file) => {
        const blobResponse = await fetchWithGitHub(file.url);
        if (!blobResponse.ok) return [];

        const blobData: GitHubBlobResponse = await blobResponse.json();
        const content = blobData.encoding === "base64"
          ? Buffer.from(blobData.content, "base64").toString("utf-8")
          : blobData.content;

        return parseDependencyFile(file.path.split("/").pop() || "", content, file.path);
      })
    );

    for (const result of depResults) {
      if (result.status === "fulfilled") {
        allDeps.push(...result.value);
      }
    }

    // 5. Query OSV for CVEs
    const cves = await queryAllDependencies(allDeps);

    // 6. Generate AI analysis (if OpenAI key is set)
    const aiAnalysis = await generateAIAnalysis(allDeps, cves, repoUrl);

    const duration = Date.now() - startTime;

    const result: CVEScanResult = {
      dependencies: allDeps,
      cves,
      aiAnalysis,
      scanDuration: duration,
    };

    return NextResponse.json(result);
  } catch (error) {
    console.error("CVE scan error:", error);
    return NextResponse.json(
      { error: "An unexpected error occurred during CVE scanning." },
      { status: 500 }
    );
  }
}
