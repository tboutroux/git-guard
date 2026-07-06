# 🛡️ GitGuard — Repository Security Scanner

GitGuard scans any **public GitHub repository** for security problems and grades the result, live in your browser:

- 🔑 **Secret detection** — AWS/GitHub/Stripe/Google keys, private keys, DB connection strings, hardcoded passwords & tokens (with placeholder/entropy filtering to cut false positives)
- ⚠️ **Unsafe code patterns** — SQL/command injection risks, `eval()` on user input, disabled TLS verification, weak crypto, debug mode left on
- 🐛 **Known CVEs** — every dependency manifest (npm, PyPI, Go, Maven, Cargo, Composer, RubyGems, …) is parsed and cross-checked against the [OSV.dev](https://osv.dev) vulnerability database
- 🤖 **AI code review** — our AI review engine reads the most security-relevant source files (routes, auth, DB access) and reports logic-level flaws that regex can't catch; if the primary engine is unavailable it **falls back to fully local inference** automatically
- 📊 **Security score & grade** — weighted 0–100 score with an A+–F grade, severity breakdown chart, and an exportable PDF report

Everything streams **live**: you watch the pipeline phases tick, the scan log scroll, and findings appear the moment they're detected.

![stack](https://img.shields.io/badge/Next.js%2015-black?logo=next.js) ![lang](https://img.shields.io/badge/TypeScript-3178c6?logo=typescript&logoColor=white) ![ai](https://img.shields.io/badge/AI%20code%20review-9085e9) ![data](https://img.shields.io/badge/OSV.dev-3987e5)

---

## How it works

```
 repo URL
    │
    ▼
┌─────────────┐   ┌──────────────┐   ┌───────────────────────┐
│ 1. resolve  │──▶│ 2. clone     │──▶│ 3. secret & pattern   │
│ GitHub API  │   │ depth-1 git  │   │    scan (regex rules) │
└─────────────┘   └──────────────┘   └───────────┬───────────┘
                                                 │
                              ┌──────────────────┴─────────────────┐
                              ▼ (parallel)                         ▼ (parallel)
                   ┌────────────────────┐             ┌─────────────────────┐
                   │ 4. dependency CVEs │             │ 5. AI code review   │
                   │ parse manifests →  │             │ rank files → AI     │
                   │ OSV.dev querybatch │             │ structured findings │
                   └──────────┬─────────┘             └──────────┬──────────┘
                              └──────────────────┬───────────────┘
                                                 ▼
                                  ┌───────────────────────────┐
                                  │ 6. weighted score + grade │
                                  └───────────────────────────┘
```

The API route (`/api/scan`) streams **NDJSON events** (`phase`, `log`, `progress`, `finding`, `cve`, `report`) over a single HTTP response; the React client folds them into live UI state. No polling, no websockets.

## Quick start

```bash
npm install
npm run dev                  # open http://localhost:3000
```

Optional `.env.local`:

```bash
# Primary AI review engine (hosted)
ANTHROPIC_API_KEY=...

# Local AI review engine (fallback when the primary one is unavailable)
OLLAMA_API_URL=http://localhost:11434
OLLAMA_MODEL=mistral

# Higher GitHub rate limits
GITHUB_TOKEN=ghp_...
```

Everything is optional: without an AI engine configured, GitGuard still does secret scanning and CVE lookup. The AI phase picks the best available engine at scan time: **primary → local → skipped**. The local engine gets a smaller file budget (CPU inference is slow), so expect fewer but still real findings from the fallback.

### Try it on a deliberately vulnerable repo

Good demo targets (all intentionally insecure teaching apps):

- `OWASP/NodeGoat` — scores **0/100 (F)**: exposed secrets, injection patterns, 16 known CVEs
- `digininja/DVWA`
- `juice-shop/juice-shop`

Then contrast with a small healthy library (e.g. `sindresorhus/slugify` → **100/100 A+**).

## Scoring

Every scan starts at **100** and deducts per finding, weighted by severity (critical −15, high −8, medium −4, …) with diminishing returns per category so one noisy rule can't zero the score alone. Dependency CVEs are weighted separately. The result maps to a grade:

| Score | ≥97 | ≥88 | ≥75 | ≥60 | ≥40 | <40 |
|---|---|---|---|---|---|---|
| Grade | A+ | A | B | C | D | F |

The full breakdown (what cost how many points) is shown in the UI and included in the exported PDF report.

## Project structure

```
src/
├── app/
│   ├── api/scan/route.ts     # streaming scan pipeline (NDJSON)
│   ├── page.tsx              # entry
│   └── globals.css           # design tokens (dark security-ops theme)
├── components/
│   ├── Scanner.tsx           # client state machine: hero → live scan → dashboard
│   ├── ScanTerminal.tsx      # pipeline checklist + live log
│   ├── ScoreGauge.tsx        # animated SVG score meter
│   ├── SeverityChart.tsx     # severity bars (+ accessible table view)
│   └── FindingCard.tsx / CveCard.tsx / severity.tsx
└── lib/
    ├── github.ts             # URL parsing, metadata, shallow clone, file walk
    ├── rules.ts              # secret & unsafe-pattern rule set
    ├── secret-scanner.ts     # rule engine + entropy/placeholder filtering
    ├── dependencies.ts       # manifest parsers (10 ecosystems)
    ├── osv.ts                # OSV.dev batch queries + CVE details
    ├── ai.ts                 # AI review engines (structured JSON output)
    ├── score.ts              # weighted scoring + grade
    ├── report-pdf.ts         # exportable PDF report (jsPDF)
    └── types.ts              # shared event & report types
```

## Design notes

- **Streaming-first UX** — a scan is a pipeline, so the UI shows the pipeline: phase checklist, terminal-style log, findings appearing live.
- **Safety of the scanner itself** — repo names are validated against `^[A-Za-z0-9_.-]+$` and passed to `git` after `--` (no argument injection); clones are depth-1 into a temp dir and deleted after every scan; detected secrets are redacted before leaving the server.
- **Accessible severity** — severity is always icon + label + color (status palette with ≥3:1 contrast on the dark surface), never color alone; the chart has a table-view twin.
- **Graceful degradation** — primary AI engine unreachable? The review falls back to local inference; nothing available? The phase is skipped and everything else still works.

## Limitations

- Public repositories only.
- Pattern rules trade recall for precision — they won't catch every secret format.
- OSV coverage depends on the manifest being parseable; lockfiles other than `Gemfile.lock` aren't read yet.
- The AI pass reviews at most ~12 high-signal files per scan to keep cost and latency bounded.
