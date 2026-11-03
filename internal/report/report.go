package report

import (
	"fmt"
	"io"
	"strings"

	"cloneguard/internal/scanner"
)

const maxPrinted = 40

type palette struct{ on bool }

func (p palette) wrap(code, s string) string {
	if !p.on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p palette) bold(s string) string { return p.wrap("1", s) }
func (p palette) dim(s string) string  { return p.wrap("2", s) }

func (p palette) sev(s scanner.Severity) string {
	label := "[" + strings.ToUpper(s.String()) + "]"
	switch s {
	case scanner.Critical:
		return p.wrap("1;97;41", label)
	case scanner.High:
		return p.wrap("1;31", label)
	case scanner.Medium:
		return p.wrap("1;33", label)
	}
	return p.wrap("36", label)
}

// Text prints a plain-English report.
func Text(w io.Writer, r *scanner.Result, color bool) {
	p := palette{on: color}

	fmt.Fprintf(w, "\n%s\n", p.bold(fmt.Sprintf("cloneguard: scanned %d files in %s", r.FilesScanned, r.Root)))

	var headline, advice string
	switch r.Verdict {
	case scanner.Dangerous:
		headline = p.wrap("1;97;41", " DANGEROUS ") + " Do not run or install anything from this project."
		advice = "Delete it. If you already ran anything from it, treat that computer as compromised: change passwords, replace SSH/cloud keys, sign out all sessions, and tell your IT or security team."
	case scanner.Suspicious:
		headline = p.wrap("1;31", "SUSPICIOUS") + " Do not run this on your main machine."
		advice = "Read the flagged files first. If you really must run it, use a throwaway virtual machine or container with no keys or accounts on it."
	case scanner.Caution:
		headline = p.wrap("1;33", "CAUTION") + " A few things are worth a look before you run it."
		advice = "Nothing here is alarming on its own, but open the flagged lines and make sure you understand them."
	default:
		headline = p.wrap("1;32", "NO RED FLAGS FOUND") + " That does not prove it is safe."
		advice = "It only means none of the common tricks were spotted. If a stranger asked you to run this, still use a throwaway virtual machine."
	}
	fmt.Fprintf(w, "\n%s\n", headline)

	if len(r.Findings) > 0 {
		fmt.Fprintf(w, "%s\n", p.dim(fmt.Sprintf("%d critical, %d high, %d medium, %d low",
			r.Count(scanner.Critical), r.Count(scanner.High), r.Count(scanner.Medium), r.Count(scanner.Low))))
	}

	seen := map[string]bool{}
	for i, f := range r.Findings {
		if i >= maxPrinted {
			fmt.Fprintf(w, "\n%s\n", p.dim(fmt.Sprintf("...and %d more findings (use --json to see all of them)", len(r.Findings)-maxPrinted)))
			break
		}
		fmt.Fprintf(w, "\n%s %s:%d  %s\n", p.sev(f.Severity), f.File, f.Line, p.bold(f.Title))
		if f.Snippet != "" {
			fmt.Fprintf(w, "    %s %s\n", p.dim(">"), f.Snippet)
		}
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			fmt.Fprintf(w, "    %s\n", wrapText(f.Why, 76, "    "))
		}
	}

	fmt.Fprintf(w, "\n%s\n%s\n", p.bold("What to do:"), wrapText(advice, 78, ""))
	fmt.Fprintf(w, "\n%s\n\n", p.dim(fmt.Sprintf("%d files skipped (docs, binaries, lockfiles, node_modules, .git, very large files).", r.FilesSkipped)))
}

// wrapText word-wraps s to width, indenting continuation lines.
func wrapText(s string, width int, indent string) string {
	words := strings.Fields(s)
	var b strings.Builder
	col := 0
	for i, word := range words {
		if i > 0 {
			if col+1+len(word) > width {
				b.WriteString("\n" + indent)
				col = 0
			} else {
				b.WriteString(" ")
				col++
			}
		}
		b.WriteString(word)
		col += len(word)
	}
	return b.String()
}
