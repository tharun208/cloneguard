package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"cloneguard/internal/report"
	"cloneguard/internal/scanner"
)

var version = "0.1.0" // overridden at release time via -ldflags

// Exit codes: 0 clean, 1 caution, 2 suspicious, 3 dangerous, 10 usage or I/O error.
const exitError = 10

const usage = `cloneguard: check a project for malware tricks BEFORE you run it

Usage:
  cloneguard clone [flags] <git-url> [dir]   clone a repo, then scan it right away
  cloneguard scan  [flags] [path]            scan a folder (default: current folder)

Flags (put them before the path):
  --json              machine-readable output
  --include-deps      also scan node_modules (slow)
  --max-size-mb N     skip files bigger than N MB (default 2)
  --no-color          plain output

Exit codes: 0 clean, 1 caution, 2 suspicious, 3 dangerous, 10 error.
cloneguard never executes anything from the project it scans.
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitError
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "version", "-v", "--version":
		fmt.Fprintln(stdout, "cloneguard", version)
		return 0
	case "clone":
		return cmdClone(args[1:], stdout, stderr)
	case "scan":
		return cmdScan(args[1:], stdout, stderr)
	}
	return cmdScan(args, stdout, stderr) // `cloneguard ./folder` shorthand
}

type commonFlags struct {
	json, deps, noColor *bool
	maxMB               *int
}

func newFlagSet(name string, stderr io.Writer) (*flag.FlagSet, commonFlags) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs, commonFlags{
		json:    fs.Bool("json", false, "machine-readable output"),
		deps:    fs.Bool("include-deps", false, "also scan node_modules"),
		noColor: fs.Bool("no-color", false, "plain output"),
		maxMB:   fs.Int("max-size-mb", 2, "skip files bigger than this many MB"),
	}
}

func cmdScan(args []string, stdout, stderr io.Writer) int {
	fs, cf := newFlagSet("scan", stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return exitError
	}
	path := "."
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}
	return scanAndReport(path, cf, stdout, stderr)
}

func cmdClone(args []string, stdout, stderr io.Writer) int {
	fs, cf := newFlagSet("clone", stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return exitError
	}
	if fs.NArg() < 1 {
		fmt.Fprint(stderr, usage)
		return exitError
	}
	url := fs.Arg(0)
	dir := dirFromURL(url)
	if fs.NArg() > 1 {
		dir = fs.Arg(1)
	}
	if dir == "" {
		fmt.Fprintln(stderr, "cloneguard: could not work out a folder name; pass one as the second argument")
		return exitError
	}

	// "--" stops a hostile URL from being read as a git option.
	cmd := exec.Command("git", "clone", "--", url, dir)
	cmd.Stdout, cmd.Stderr = stderr, stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(stderr, "cloneguard: git clone failed:", err)
		return exitError
	}
	fmt.Fprintf(stderr, "\nCloned into %s. Downloading does not run anything from the project. Scanning it now...\n", dir)
	return scanAndReport(dir, cf, stdout, stderr)
}

func scanAndReport(path string, cf commonFlags, stdout, stderr io.Writer) int {
	opts := scanner.DefaultOptions()
	opts.IncludeDeps = *cf.deps
	if *cf.maxMB > 0 {
		opts.MaxFileSize = int64(*cf.maxMB) << 20
	}
	res, err := scanner.Scan(path, opts)
	if err != nil {
		fmt.Fprintln(stderr, "cloneguard:", err)
		return exitError
	}
	if *cf.json {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintln(stderr, "cloneguard:", err)
			return exitError
		}
	} else {
		report.Text(stdout, res, useColor(stdout, *cf.noColor))
	}
	return int(res.Verdict)
}

func useColor(w io.Writer, noColor bool) bool {
	if noColor || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func dirFromURL(u string) string {
	u = strings.TrimSuffix(strings.TrimRight(u, "/"), ".git")
	if i := strings.LastIndexAny(u, "/:"); i >= 0 {
		u = u[i+1:]
	}
	if u == "" || u == "." || u == ".." {
		return ""
	}
	return u
}
