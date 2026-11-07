package scanner

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const maxHitsPerRulePerFile = 5

type fileKind int

const (
	kindSkip fileKind = iota
	kindCode
	kindConfig
	kindDoc
	kindOther
)

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, i := range items {
		m[i] = true
	}
	return m
}

var (
	codeExts = set(".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".py", ".go", ".sh", ".bash", ".zsh",
		".rb", ".php", ".ps1", ".bat", ".cmd", ".java", ".kt", ".cs", ".rs", ".pl", ".lua", ".vbs", ".scpt")
	configExts = set(".json", ".jsonc", ".yml", ".yaml", ".toml", ".env", ".ini", ".cfg", ".conf", ".mk")
	docExts    = set(".md", ".markdown", ".txt", ".rst", ".adoc")
	execExts   = set(".exe", ".dll", ".scr", ".msi", ".dylib", ".so", ".node", ".pkg", ".dmg", ".apk", ".com", ".sys")
	lockfiles  = set("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.sum", "cargo.lock",
		"poetry.lock", "composer.lock", "gemfile.lock", "pipfile.lock")
	skipDirs = set(".git", "node_modules", "__pycache__", ".venv", "venv")
)

var (
	obfuscatedIdent = rx(`\b_0x[0-9a-fA-F]{3,6}\b`)
	// Calls that actually send data somewhere (a bare URL in a comment does not count).
	netCall       = rx(`(?i)\bfetch\s*\(|\baxios\b|\brequests\.(get|post|put)\b|\burllib\b|\bhttps?\.(request|get|post)\b|\bhttp\.(Get|Post|NewRequest)\b|\bnet\.Dial\b|\bnet\.(connect|createConnection)\b|\bsocket\.(create_connection|socket)\b|TcpStream::connect|TCPSocket\.new|XMLHttpRequest|\bWebSocket\s*\(|\.post\s*\(|\bcurl\b|\bwget\b`)
	whitespaceRun = rx(`[ \t]{3,}`)
)

// Scan walks root and returns everything suspicious it found.
func Scan(root string, opts Options) (*Result, error) {
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = DefaultOptions().MaxFileSize
	}
	root = filepath.Clean(root)
	if _, err := os.Stat(root); err != nil {
		return nil, err
	}
	res := &Result{Root: root, Findings: []Finding{}}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			res.FilesSkipped++
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if path != root && skipDirs[d.Name()] && !(opts.IncludeDeps && d.Name() == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() { // symlinks, sockets, devices
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		scanFile(res, opts, path, rel, d)
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.RuleID < b.RuleID
	})
	res.Verdict = verdictFor(res.Findings)
	res.VerdictText = res.Verdict.String()
	return res, nil
}

func verdictFor(fs []Finding) Verdict {
	v := Clean
	for _, f := range fs {
		switch f.Severity {
		case Critical:
			return Dangerous
		case High:
			if v < Suspicious {
				v = Suspicious
			}
		case Medium:
			if v < Caution {
				v = Caution
			}
		}
	}
	return v
}

func classify(base string) fileKind {
	lower := strings.ToLower(base)
	if lockfiles[lower] || strings.HasSuffix(lower, ".map") {
		return kindSkip
	}
	ext := filepath.Ext(lower)
	switch {
	case codeExts[ext]:
		return kindCode
	case strings.HasPrefix(lower, ".env"), configExts[ext], lower == "makefile", lower == "dockerfile":
		return kindConfig
	case docExts[ext]:
		return kindDoc
	}
	return kindOther
}

func scanFile(res *Result, opts Options, path, rel string, d fs.DirEntry) {
	base := d.Name()
	kind := classify(base)
	if kind == kindSkip || kind == kindDoc {
		res.FilesSkipped++
		return
	}
	info, err := d.Info()
	if err != nil {
		res.FilesSkipped++
		return
	}
	if info.Size() > opts.MaxFileSize {
		res.FilesSkipped++
		if kind == kindCode || kind == kindConfig {
			res.Findings = append(res.Findings, Finding{
				RuleID: "large-file-not-scanned", Title: "Large source file was not scanned", Severity: Low,
				File: rel, Line: 1,
				Why: "This file is bigger than the scan limit, so it was skipped. Big source files can hide things.",
			})
		}
		return
	}
	content, err := os.ReadFile(path)
	if err != nil {
		res.FilesSkipped++
		return
	}

	head := content
	if len(head) > 8000 {
		head = head[:8000]
	}
	if bytes.IndexByte(head, 0) >= 0 { // binary
		res.FilesSkipped++
		if looksExecutable(head, strings.ToLower(filepath.Ext(base))) {
			res.Findings = append(res.Findings, Finding{
				RuleID: "contains-executable-binary", Title: "Compiled program inside the repo", Severity: Medium,
				File: rel, Line: 1,
				Why: "A ready-made program is checked into the project. You cannot read what it does, and a project you are asked to \"just run\" should not need one.",
			})
		}
		return
	}

	res.FilesScanned++
	res.Findings = append(res.Findings, scanText(rel, base, kind, content)...)
	res.Findings = append(res.Findings, fileChecks(rel, base, content)...)
}

func looksExecutable(b []byte, ext string) bool {
	if len(b) >= 4 {
		if b[0] == 'M' && b[1] == 'Z' {
			return true
		}
		if bytes.HasPrefix(b, []byte{0x7f, 'E', 'L', 'F'}) {
			return true
		}
		for _, magic := range [][]byte{
			{0xfe, 0xed, 0xfa, 0xce}, {0xfe, 0xed, 0xfa, 0xcf},
			{0xce, 0xfa, 0xed, 0xfe}, {0xcf, 0xfa, 0xed, 0xfe},
			{0xca, 0xfe, 0xba, 0xbe},
		} {
			if bytes.HasPrefix(b, magic) {
				return true
			}
		}
	}
	return execExts[ext]
}

func inScope(k fileKind, s scope) bool {
	switch s {
	case scopeCode:
		return k == kindCode
	case scopeCodeConfig:
		return k == kindCode || k == kindConfig
	case scopeAnyText:
		return k == kindCode || k == kindConfig || k == kindOther
	}
	return false
}

// scanText runs the per-line rules, then looks for dangerous combinations in the same file.
func scanText(rel, base string, kind fileKind, content []byte) []Finding {
	var out []Finding
	hits := map[string]int{}
	var hasCred, hasDyn, hasSusNet, hasObf bool
	var firstCred, firstDyn, firstObf int

	text := string(content)
	lines := strings.Split(text, "\n")
	matched := make([]int, 0, 4)

	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		matched = matched[:0]
		locs := map[int][2]int{}
		for ri := range lineRules {
			r := &lineRules[ri]
			if !inScope(kind, r.scope) {
				continue
			}
			loc := r.re.FindStringIndex(line)
			if loc == nil {
				continue
			}
			if r.exclude != nil && r.exclude.MatchString(line) {
				continue
			}
			matched = append(matched, ri)
			locs[ri] = [2]int{loc[0], loc[1]}
		}
		if len(matched) == 0 {
			continue
		}
		suppressed := map[string]bool{}
		for _, ri := range matched {
			for _, id := range lineRules[ri].suppresses {
				suppressed[id] = true
			}
		}
		for _, ri := range matched {
			r := &lineRules[ri]
			switch r.cat {
			case catCredentials:
				if !hasCred {
					hasCred, firstCred = true, i+1
				}
			case catDynamicExec:
				if !hasDyn {
					hasDyn, firstDyn = true, i+1
				}
			case catNetwork:
				hasSusNet = true
			case catObfuscation:
				if !hasObf {
					hasObf, firstObf = true, i+1
				}
			}
			if suppressed[r.id] {
				continue
			}
			hits[r.id]++
			if hits[r.id] > maxHitsPerRulePerFile {
				continue
			}
			out = append(out, Finding{
				RuleID: r.id, Title: r.title, Severity: r.sev, File: rel, Line: i + 1,
				Snippet: snippet(line, locs[ri][0], locs[ri][1]), Why: r.why,
			})
		}
	}

	// Machine-made variable names like _0x4f2a are the fingerprint of javascript-obfuscator.
	if kind == kindCode {
		if idx := obfuscatedIdent.FindAllStringIndex(text, 10); len(idx) >= 10 {
			hasObf = true
			firstObf = strings.Count(text[:idx[0][0]], "\n") + 1
			out = append(out, Finding{
				RuleID: "obfuscated-identifiers", Title: "Deliberately scrambled code", Severity: High,
				File: rel, Line: firstObf,
				Why: "Dozens of machine-generated names like _0x4f2a mean this file was run through an obfuscator. Honest projects ship readable source.",
			})
		}
	}

	callsNetwork := hasSusNet || netCall.MatchString(text)
	switch {
	case hasCred && hasSusNet:
		out = append(out, Finding{
			RuleID: "reads-credentials-and-sends-data-out", Title: "Reaches for your secrets AND talks to a suspicious server", Severity: Critical,
			File: rel, Line: firstCred,
			Why: "This one file both goes after credential files and contains a suspicious network destination. That combination is exactly how credential stealers work.",
		})
	case hasCred && callsNetwork:
		out = append(out, Finding{
			RuleID: "reads-credentials-near-network-code", Title: "Reaches for your secrets and can send data out", Severity: High,
			File: rel, Line: firstCred,
			Why: "This file touches credential files and also makes network requests. It may be innocent, but check where the data goes.",
		})
	}
	if hasDyn && hasSusNet {
		out = append(out, Finding{
			RuleID: "runs-code-from-suspicious-source", Title: "Downloads from a suspicious place and runs it", Severity: Critical,
			File: rel, Line: firstDyn,
			Why: "This file runs code dynamically and also points at a suspicious address. That is how a harmless-looking project pulls in malware later.",
		})
	}
	if hasObf && (hasCred || hasSusNet || hasDyn) {
		out = append(out, Finding{
			RuleID: "obfuscated-and-suspicious", Title: "Scrambled code with suspicious behaviour", Severity: Critical,
			File: rel, Line: firstObf,
			Why: "Hidden code that also reaches for secrets, runs dynamic code or contacts a suspicious address. There is rarely an innocent reason for all of that together.",
		})
	}
	return out
}

func snippet(line string, from, to int) string {
	start := from - 50
	if start < 0 {
		start = 0
	}
	end := to + 60
	if end > len(line) {
		end = len(line)
	}
	s := strings.ToValidUTF8(line[start:end], "")
	s = whitespaceRun.ReplaceAllString(strings.TrimSpace(s), " … ")
	if len(s) > 220 {
		s = strings.ToValidUTF8(s[:220], "") + "…"
	}
	if start > 0 {
		s = "…" + s
	}
	return s
}

func lineOf(content []byte, needle string) int {
	i := bytes.Index(content, []byte(needle))
	if i < 0 {
		return 1
	}
	return bytes.Count(content[:i], []byte("\n")) + 1
}

var _ = regexp.MustCompile // keep regexp imported for rx users in this package
