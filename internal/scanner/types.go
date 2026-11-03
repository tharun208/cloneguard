package scanner

// Severity says how worrying a single finding is.
type Severity int

const (
	Low Severity = iota + 1
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	case Critical:
		return "critical"
	}
	return "unknown"
}

// MarshalText makes severities show up as words in JSON output.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Finding is one suspicious thing spotted in one file.
type Finding struct {
	RuleID   string   `json:"rule"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Snippet  string   `json:"snippet,omitempty"`
	Why      string   `json:"why"`
}

// Verdict is the overall call for the whole repo.
type Verdict int

const (
	Clean Verdict = iota
	Caution
	Suspicious
	Dangerous
)

func (v Verdict) String() string {
	switch v {
	case Caution:
		return "caution"
	case Suspicious:
		return "suspicious"
	case Dangerous:
		return "dangerous"
	}
	return "clean"
}

// Result is everything a scan produced.
type Result struct {
	Root         string    `json:"root"`
	FilesScanned int       `json:"files_scanned"`
	FilesSkipped int       `json:"files_skipped"`
	Findings     []Finding `json:"findings"`
	Verdict      Verdict   `json:"-"`
	VerdictText  string    `json:"verdict"`
}

// Count returns how many findings have the given severity.
func (r *Result) Count(s Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == s {
			n++
		}
	}
	return n
}

// Options tunes a scan.
type Options struct {
	// IncludeDeps also scans node_modules (skipped by default; it is huge).
	IncludeDeps bool
	// MaxFileSize is the biggest file (bytes) that will be read.
	MaxFileSize int64
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{MaxFileSize: 2 << 20}
}
