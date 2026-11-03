package scanner

import (
	"encoding/json"
	"sort"
	"strings"
)

var (
	installHooks = set("preinstall", "install", "postinstall", "prepare", "prepublish")

	// Hooks that nearly every legitimate project uses; not worth a warning.
	benignHook = rx(`(?i)^\s*(husky(\s+install)?(\s+\S+)?|patch-package|simple-git-hooks|lefthook\s+install|(npm|pnpm|yarn)(\s+run)?\s+build|tsc(\s+-b|\s+-p\s+\S+)?|node-gyp\s+rebuild|prisma\s+generate|(npx\s+)?only-allow\s+\w+|electron-builder\s+install-app-deps)\s*$`)

	riskyHook   = rx(`(?i)\bcurl\b|\bwget\b|node\s+-e\b|\beval\b|base64|powershell|\bsh\s+-c\b|\|\s*(ba|z)?sh\b|https?://|/tmp/|\.\./\.\.`)
	riskyScript = rx(`(?i)\bcurl\b|\bwget\b|node\s+-e\b|base64|powershell|\|\s*(ba|z)?sh\b|\beval\b`)

	folderOpen  = rx(`"runOn"\s*:\s*"folderOpen"`)
	autoTasksOn = rx(`"task\.allowAutomaticTasks"\s*:\s*"on"`)
	riskyTask   = rx(`(?i)\bcurl\b|\bwget\b|powershell|base64|\bbash\b|\bsh\s+-c\b|https?://|cmd(\.exe)?\s+/c`)

	pySetupRisky = rx(`(?i)cmdclass|os\.system|subprocess|urlopen|urllib|requests\.`)
)

// fileChecks handles files whose danger comes from what they are, not from a single line.
func fileChecks(rel, base string, content []byte) []Finding {
	var out []Finding
	lower := strings.ToLower(base)

	switch {
	case lower == "package.json":
		out = append(out, packageJSON(rel, content)...)

	case strings.HasSuffix(rel, ".vscode/tasks.json") || rel == ".vscode/tasks.json":
		if folderOpen.Match(content) {
			sev := High
			if riskyTask.Match(content) {
				sev = Critical
			}
			out = append(out, Finding{
				RuleID: "auto-runs-on-folder-open", Title: "Runs a command the moment you open the folder", Severity: sev,
				File: rel, Line: lineOf(content, "folderOpen"),
				Why: "VS Code and forks like Cursor can be told to run a command as soon as this folder is opened, with no click from you. It is a known trick in fake-job-interview attacks. Say no if your editor asks to trust the folder.",
			})
		}

	case strings.HasSuffix(rel, ".vscode/settings.json") || rel == ".vscode/settings.json":
		if autoTasksOn.Match(content) {
			out = append(out, Finding{
				RuleID: "allows-automatic-tasks", Title: "Switches on auto-running editor tasks", Severity: High,
				File: rel, Line: lineOf(content, "allowAutomaticTasks"),
				Why: "This setting lets the project's tasks start on their own when you open it, which removes a safety prompt.",
			})
		}

	case lower == "setup.py":
		if pySetupRisky.Match(content) {
			out = append(out, Finding{
				RuleID: "python-install-runs-code", Title: "Python install step runs custom code", Severity: Medium,
				File: rel, Line: 1,
				Why: "setup.py runs while you pip install the project, and this one runs commands or downloads things. Read it before installing.",
			})
		}
	}
	return out
}

func packageJSON(rel string, content []byte) []Finding {
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if json.Unmarshal(content, &pkg) != nil {
		return nil
	}
	names := make([]string, 0, len(pkg.Scripts))
	for n := range pkg.Scripts {
		names = append(names, n)
	}
	sort.Strings(names)

	var out []Finding
	for _, name := range names {
		cmd := pkg.Scripts[name]
		line := lineOf(content, `"`+name+`"`)
		isHook := installHooks[name]
		switch {
		case isHook && benignHook.MatchString(cmd):
			continue
		case isHook && riskyHook.MatchString(cmd):
			out = append(out, Finding{
				RuleID: "risky-install-script", Title: "Install script looks dangerous", Severity: High,
				File: rel, Line: line, Snippet: name + ": " + cmd,
				Why: "npm runs this automatically the moment you type npm install, before you have looked at anything, and this one downloads or hides something.",
			})
		case isHook:
			out = append(out, Finding{
				RuleID: "runs-on-install", Title: "Runs a script automatically on install", Severity: Medium,
				File: rel, Line: line, Snippet: name + ": " + cmd,
				Why: "npm runs this automatically when you type npm install. Open the script it points to and read it first.",
			})
		case riskyScript.MatchString(cmd):
			out = append(out, Finding{
				RuleID: "risky-npm-script", Title: "npm script downloads or hides something", Severity: High,
				File: rel, Line: line, Snippet: name + ": " + cmd,
				Why: "This script fetches something from the internet, decodes hidden text or pipes into a shell when you run it.",
			})
		}
	}
	return out
}
