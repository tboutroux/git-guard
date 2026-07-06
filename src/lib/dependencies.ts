import type { DependencyInfo } from "./types";

type Parser = (content: string, path: string) => DependencyInfo[];

const PARSERS: Record<string, Parser> = {
  "package.json": parsePackageJson,
  "requirements.txt": parseRequirementsTxt,
  "Pipfile": parsePipfile,
  "Gemfile.lock": parseGemfileLock,
  "go.mod": parseGoMod,
  "pom.xml": parsePomXml,
  "build.gradle": parseBuildGradle,
  "Cargo.toml": parseCargoToml,
  "composer.json": parseComposerJson,
  "pyproject.toml": parsePyprojectToml,
};

export function isDependencyFile(path: string): boolean {
  return (path.split("/").pop() ?? "") in PARSERS;
}

export function parseDependencies(path: string, content: string): DependencyInfo[] {
  const parser = PARSERS[path.split("/").pop() ?? ""];
  if (!parser) return [];
  try {
    return parser(content, path);
  } catch {
    return [];
  }
}

export function dedupeDependencies(deps: DependencyInfo[]): DependencyInfo[] {
  const seen = new Set<string>();
  return deps.filter((d) => {
    const key = `${d.ecosystem}:${d.name}@${d.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function cleanVersion(v: string): string {
  return v.replace(/^[\^~>=<!=v\s]+/, "").trim();
}

function parsePackageJson(content: string, path: string): DependencyInfo[] {
  const deps: DependencyInfo[] = [];
  const pkg = JSON.parse(content);
  for (const section of ["dependencies", "devDependencies"]) {
    const entries = pkg[section];
    if (!entries || typeof entries !== "object") continue;
    for (const [name, raw] of Object.entries(entries)) {
      const version = cleanVersion(String(raw));
      if (/^\d/.test(version)) deps.push({ name, version, ecosystem: "npm", source: path });
    }
  }
  return deps;
}

function parseRequirementsTxt(content: string, path: string): DependencyInfo[] {
  const deps: DependencyInfo[] = [];
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-")) continue;
    const match = trimmed.match(/^([A-Za-z0-9_\-.]+)\s*(?:\[[^\]]*\])?\s*[=~!><]=*\s*([0-9][^\s,;]*)/);
    if (match) deps.push({ name: match[1], version: match[2], ecosystem: "PyPI", source: path });
  }
  return deps;
}

function parsePipfile(content: string, path: string): DependencyInfo[] {
  const deps: DependencyInfo[] = [];
  let inDeps = false;
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (/^\[(packages|dev-packages)\]/.test(trimmed)) { inDeps = true; continue; }
    if (trimmed.startsWith("[")) { inDeps = false; continue; }
    if (!inDeps) continue;
    const match = trimmed.match(/^([A-Za-z0-9_\-.]+)\s*=\s*"([^"]+)"/);
    if (match && match[2] !== "*") {
      deps.push({ name: match[1], version: cleanVersion(match[2]), ecosystem: "PyPI", source: path });
    }
  }
  return deps;
}

function parseGemfileLock(content: string, path: string): DependencyInfo[] {
  const deps: DependencyInfo[] = [];
  for (const line of content.split("\n")) {
    const match = line.match(/^\s{4}([A-Za-z0-9_\-.]+)\s+\((\d[^)]*)\)/);
    if (match) deps.push({ name: match[1], version: match[2], ecosystem: "RubyGems", source: path });
  }
  return deps;
}

function parseGoMod(content: string, path: string): DependencyInfo[] {
  const deps: DependencyInfo[] = [];
  let inRequire = false;
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.startsWith("require (")) { inRequire = true; continue; }
    if (inRequire && trimmed === ")") { inRequire = false; continue; }
    const target = inRequire ? trimmed : trimmed.startsWith("require ") ? trimmed.slice(8) : null;
    if (!target) continue;
    const match = target.match(/^([^\s]+)\s+v([0-9][^\s]*)/);
    if (match) deps.push({ name: match[1], version: match[2], ecosystem: "Go", source: path });
  }
  return deps;
}

function parsePomXml(content: string, path: string): DependencyInfo[] {
  const deps: DependencyInfo[] = [];
  const depRegex = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*<version>([^<$]+)<\/version>/g;
  let match: RegExpExecArray | null;
  while ((match = depRegex.exec(content)) !== null) {
    deps.push({ name: `${match[1]}:${match[2]}`, version: match[3].trim(), ecosystem: "Maven", source: path });
  }
  return deps;
}

function parseBuildGradle(content: string, path: string): DependencyInfo[] {
  const deps: DependencyInfo[] = [];
  const gradleRegex = /(?:implementation|api|compile|runtimeOnly|testImplementation)\s+['"]([^:'"]+):([^:'"]+):([^'"$]+)['"]/g;
  let match: RegExpExecArray | null;
  while ((match = gradleRegex.exec(content)) !== null) {
    deps.push({ name: `${match[1]}:${match[2]}`, version: match[3], ecosystem: "Maven", source: path });
  }
  return deps;
}

function parseCargoToml(content: string, path: string): DependencyInfo[] {
  const deps: DependencyInfo[] = [];
  let inDeps = false;
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (/^\[.*dependencies.*\]$/.test(trimmed)) { inDeps = true; continue; }
    if (trimmed.startsWith("[")) { inDeps = false; continue; }
    if (!inDeps) continue;
    const simple = trimmed.match(/^([A-Za-z0-9_\-.]+)\s*=\s*"([^"]+)"/);
    const complex = trimmed.match(/^([A-Za-z0-9_\-.]+)\s*=\s*\{.*version\s*=\s*"([^"]+)"/);
    const m = simple ?? complex;
    if (m) deps.push({ name: m[1], version: cleanVersion(m[2]), ecosystem: "crates.io", source: path });
  }
  return deps;
}

function parseComposerJson(content: string, path: string): DependencyInfo[] {
  const deps: DependencyInfo[] = [];
  const pkg = JSON.parse(content);
  for (const section of ["require", "require-dev"]) {
    const entries = pkg[section];
    if (!entries || typeof entries !== "object") continue;
    for (const [name, raw] of Object.entries(entries)) {
      if (name === "php" || name.startsWith("ext-")) continue;
      const version = cleanVersion(String(raw));
      if (/^\d/.test(version)) deps.push({ name, version, ecosystem: "Packagist", source: path });
    }
  }
  return deps;
}

function parsePyprojectToml(content: string, path: string): DependencyInfo[] {
  const deps: DependencyInfo[] = [];
  const section = content.match(/\[project\][\s\S]*?dependencies\s*=\s*\[([\s\S]*?)\]/);
  if (!section) return deps;
  for (const m of section[1].matchAll(/"([A-Za-z0-9_\-.]+)\s*(?:\[[^\]]*\])?\s*[><=!~]+\s*([0-9][^",]*)"/g)) {
    deps.push({ name: m[1], version: m[2].trim(), ecosystem: "PyPI", source: path });
  }
  return deps;
}
