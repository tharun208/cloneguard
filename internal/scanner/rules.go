package scanner

import "regexp"

// scope decides which kinds of files a line rule applies to.
type scope int

const (
	scopeCode       scope = iota + 1 // source code only
	scopeCodeConfig                  // code + json/yaml/env/Makefile/etc.
	scopeAnyText                     // every text file except docs and lockfiles
)

// category groups rules so we can spot dangerous combinations in one file.
type category int

const (
	catNone category = iota
	catCredentials
	catNetwork
	catDynamicExec
	catObfuscation
)

type lineRule struct {
	id         string
	title      string
	sev        Severity
	cat        category
	scope      scope
	re         *regexp.Regexp
	exclude    *regexp.Regexp // if this also matches the line, ignore the hit
	suppresses []string       // lower-level rules this one makes redundant on the same line
	why        string
}

func rx(s string) *regexp.Regexp { return regexp.MustCompile(s) }

var lineRules = []lineRule{
	// ---- Reaching for your secrets ------------------------------------
	{
		id: "reads-ssh-keys", title: "Touches your SSH keys", sev: High, cat: catCredentials, scope: scopeCode,
		re:  rx(`(?i)\.ssh\b|\bid_(rsa|ed25519|ecdsa|dsa)\b|\bauthorized_keys\b`),
		why: "This code reaches into your ~/.ssh folder, where your private SSH keys live. A normal app has no reason to touch it.",
	},
	{
		id: "reads-cloud-credentials", title: "Touches cloud or tool credentials", sev: High, cat: catCredentials, scope: scopeCode,
		re:  rx(`(?i)\.aws[/\\]+(credentials|config)|\.config[/\\]+gcloud|\.azure[/\\]|\.kube[/\\]+config|\.docker[/\\]+config\.json|\.npmrc\b|\.netrc\b|\.git-credentials|\.pypirc\b`),
		why: "This code looks at files where AWS, Google Cloud, Kubernetes, npm or Git keep their login tokens.",
	},
	{
		id: "reads-shell-files", title: "Reads shell history or dotfiles", sev: Medium, cat: catCredentials, scope: scopeCode,
		re:  rx(`(?i)\.(zsh|bash)_history|\.zshrc\b|\.bashrc\b|\.zprofile\b|\.bash_profile\b`),
		why: "Shell history and config files often contain tokens and passwords that were pasted into commands.",
	},
	{
		id: "reads-browser-or-wallet-data", title: "Touches browser passwords or crypto wallets", sev: High, cat: catCredentials, scope: scopeCode,
		re:  rx(`Login Data|Local Extension Settings|nkbihfbeogaeaoehlefnkodbefgpgknn|Library/Keychains|login\.keychain|wallet\.dat|\.solana/id\.json|Cookies\.sqlite|logins\.json|key4\.db`),
		why: "These are the places browsers store saved passwords and cookies, and where wallet extensions keep keys. Stealers go straight for them.",
	},
	{
		id: "dumps-environment", title: "Dumps all environment variables", sev: Medium, cat: catCredentials, scope: scopeCode,
		re:  rx(`JSON\.stringify\(\s*process\.env\s*\)|Object\.(entries|keys|values)\(\s*process\.env\s*\)|\bdict\(\s*os\.environ\s*\)|json\.dumps\(\s*(dict\()?os\.environ`),
		why: "Collecting every environment variable in one go also collects any API keys and tokens set on your machine.",
	},

	// ---- Talking to suspicious places --------------------------------
	{
		id: "sends-to-ip-address", title: "Connects to a raw IP address", sev: Medium, cat: catNetwork, scope: scopeCodeConfig,
		re:      rx(`https?://\d{1,3}(\.\d{1,3}){3}\b`),
		exclude: rx(`https?://(127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.)`),
		why:     "The code talks to a bare IP address instead of a named website. Legitimate apps almost always use a domain name.",
	},
	{
		id: "connects-by-socket-to-ip", title: "Opens a raw socket to an IP address", sev: Medium, cat: catNetwork, scope: scopeCode,
		re: rx(`(?i)(\bnet\.(connect|createConnection)|\bsocket\.(create_connection|socket)|\.connect\s*\(|TcpStream::connect|TCPSocket\.new|\bnet\.Dial)[^\n]{0,80}?\b\d{1,3}(\.\d{1,3}){3}\b`),
		// Quote-anchored so "110.x" is not mistaken for "10.x".
		exclude: rx(`["'](127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.)`),
		why:     "The code opens a plain network socket straight to a bare IP address, with no web address involved. Stolen files are often sent this way because it looks nothing like a normal web request.",
	},
	{
		id: "uses-dropoff-service", title: "Uses a known data drop-off service", sev: High, cat: catNetwork, scope: scopeCodeConfig,
		re:  rx(`(?i)discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com/raw|\bhastebin\b|transfer\.sh|\bfile\.io\b|webhook\.site|requestbin|pipedream\.net|interact\.sh|oast\.(pro|live|site|online|fun|me)\b`),
		why: "Webhooks, paste sites and request catchers are popular places for stolen data to be sent, because they are free and anonymous.",
	},
	{
		id: "uses-tunnel-service", title: "Uses a public tunnel service", sev: Medium, cat: catNone, scope: scopeCodeConfig,
		re:  rx(`(?i)\bngrok(-free)?\.(io|app|dev)\b|\.trycloudflare\.com|\bserveo\.net\b|\blocaltunnel\.me\b|\.loca\.lt\b`),
		why: "Tunnel services make a server on someone's laptop reachable from the internet. Fine for dev work, but also a cheap way to hide an attacker's server.",
	},
	{
		id: "base64-encoded-url", title: "Web address hidden as base64", sev: High, cat: catNetwork, scope: scopeAnyText,
		re:  rx(`aHR0c(Dov|HM6)[A-Za-z0-9+/=_-]{6,}`),
		why: "\"aHR0c\" is how \"http\" looks once it is base64-encoded. Honest code has no need to disguise where it connects.",
	},

	// ---- Running code it should not ----------------------------------
	{
		id: "runs-downloaded-or-decoded-code", title: "Runs code it just downloaded or decoded", sev: High, cat: catDynamicExec, scope: scopeCode,
		re:         rx(`\b(eval|exec)\s*\(\s*(await\s+)?(res|resp|response|body|requests\.|urllib|base64\.|zlib\.|marshal\.|codecs\.|atob\s*\(|Buffer\.from\s*\()`),
		suppresses: []string{"runs-dynamic-code"},
		why:        "The program fetches or decodes text and immediately executes it as code. That lets an attacker change what it does at any time, after you have reviewed it.",
	},
	{
		id: "builds-function-from-text", title: "Builds a function out of plain text", sev: High, cat: catDynamicExec, scope: scopeCode,
		re:         rx(`Function\.constructor|\.constructor\s*\(\s*["']return|\(\s*0\s*,\s*eval\s*\)|new\s+Function\s*\(\s*["']require["']`),
		suppresses: []string{"runs-dynamic-code"},
		why:        "This is a trick for running text as code while dodging simple scanners. It is a hallmark of malware in fake-job-interview projects.",
	},
	{
		id: "runs-dynamic-code", title: "Runs text as code (eval)", sev: Medium, cat: catDynamicExec, scope: scopeCode,
		re:  rx(`\beval\s*\(|\bnew\s+Function\s*\(|\bvm\.(runIn\w+|Script)\b`),
		why: "Turning text into running code makes it hard to see what a program really does, and is a common way to hide a payload.",
	},
	{
		id: "pipes-download-into-shell", title: "Downloads a script and runs it blind", sev: High, cat: catDynamicExec, scope: scopeCodeConfig,
		re:  rx(`(?i)\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\b(iwr|invoke-webrequest|irm|invoke-restmethod)\b[^|\n]*\|\s*(iex|invoke-expression)\b`),
		why: "A command downloads a script and feeds it straight to the shell, with no chance for anyone to read it first.",
	},
	{
		id: "hidden-powershell-or-lolbin", title: "Stealthy Windows command", sev: High, cat: catDynamicExec, scope: scopeCodeConfig,
		re:  rx(`(?i)powershell[^\n]*(\s-enc\w*|\s-w(indowstyle)?\s+hidden|\s-ep\s+bypass|\s-executionpolicy\s+bypass)|\bmshta\b|certutil\s+-urlcache|bitsadmin\s+/transfer`),
		why: "Hidden windows, encoded commands and built-in Windows download tools are standard ways of quietly installing malware.",
	},

	// ---- Spying -------------------------------------------------------
	{
		id: "watches-clipboard-or-keyboard", title: "Watches clipboard, keys or screen", sev: Medium, cat: catNone, scope: scopeCode,
		re:      rx(`(?i)\bclipboardy?\.(read|readSync)\b|clipboard\.readText|\bpynput\b|keyboard\.(on_press|hook)|\brobotjs\b|GetAsyncKeyState|\bpyperclip\.paste|screenshot-desktop|\bImageGrab\b`),
		exclude: rx(`navigator\.clipboard`),
		why:     "Reading your clipboard, keystrokes or screen is how stealers grab passwords and wallet seed phrases. Very few ordinary apps need it.",
	},

	// ---- Hiding what the code does ------------------------------------
	{
		id: "hidden-after-whitespace", title: "Code hidden far off-screen", sev: High, cat: catObfuscation, scope: scopeCode,
		re:  rx(`\S[ \t]{120,}\S`),
		why: "Real code sits after a very long run of spaces, so you would never see it without scrolling sideways. It is a deliberate hiding trick.",
	},
	{
		id: "hex-escaped-string", title: "Text hidden as hex escapes", sev: Medium, cat: catObfuscation, scope: scopeCode,
		re:  rx(`(\\x[0-9a-fA-F]{2}){12,}`),
		why: "Long strings written as hex escapes are unreadable on purpose.",
	},
	{
		id: "char-code-array", title: "Text hidden as a list of numbers", sev: Medium, cat: catObfuscation, scope: scopeCode,
		re:  rx(`String\.fromCharCode\(\s*(\d+\s*,\s*){12,}`),
		why: "Spelling out text as character numbers is a way to hide strings such as URLs or commands.",
	},
	{
		id: "long-base64-blob", title: "Huge opaque blob inside source code", sev: Medium, cat: catNone, scope: scopeCode,
		re:      rx(`[A-Za-z0-9+/]{400,}={0,2}`),
		exclude: rx(`data:[\w/+.-]+;base64`),
		why:     "A very long run of encoded text in a source file can be a second program in disguise.",
	},
}
