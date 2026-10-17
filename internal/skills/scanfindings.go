package skills

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/penguinpowernz/fogbot/internal/notifier"
)

// Finding is one thing a scanner such as rkhunter or chkrootkit reported in
// a scan
type Finding struct {
	// Check is the test that reported it, or the scanner's headline for it
	Check string
	// Lines are the details the scanner gave: files, processes, interfaces
	Lines []string
	// Infected is a rootkit or malware match, rather than something merely
	// suspicious
	Infected bool
}

// ReportOptions says which of a scan's findings to alert on
type ReportOptions struct {
	// Warnings alerts on findings that aren't infections
	Warnings bool
	// Infections alerts on rootkit and malware matches, in every scan they
	// appear in
	Infections bool
	// RepeatWarnings alerts on warnings in every scan, not just when they
	// are new
	RepeatWarnings bool
}

// Reported is a finding to alert on
type Reported struct {
	Finding
	// New is whether the finding, or some of its lines, wasn't in the
	// previous scan
	New bool
}

// Reportable returns the findings in cur to alert on, given the previous
// scan's. Scanners report the same harmless things scan after scan, so
// unless opts.RepeatWarnings is set a warning is only reported when its check
// wasn't reported before, and then with just its new lines. An infection is
// reported in full every time. prev is nil when there is no previous scan,
// making everything new.
func Reportable(prev, cur []Finding, opts ReportOptions) []Reported {
	seen := make(map[string]map[string]bool, len(prev))
	for _, f := range prev {
		lines := seen[f.Check]
		if lines == nil {
			lines = make(map[string]bool)
			seen[f.Check] = lines
		}
		for _, l := range f.Lines {
			lines[l] = true
		}
	}

	var out []Reported
	for _, f := range cur {
		fresh, isNew := f, true
		if lines, ok := seen[f.Check]; ok {
			fresh.Lines = nil
			for _, l := range f.Lines {
				if !lines[l] {
					fresh.Lines = append(fresh.Lines, l)
				}
			}
			isNew = len(fresh.Lines) > 0
		}

		switch {
		case f.Infected:
			if opts.Infections {
				out = append(out, Reported{Finding: f, New: isNew})
			}
		case !opts.Warnings:
		case isNew:
			out = append(out, Reported{Finding: fresh, New: true})
		case opts.RepeatWarnings:
			out = append(out, Reported{Finding: f})
		}
	}
	return out
}

// CleanText replaces anything that isn't plainly visible text. Scanner
// output quotes file names an attacker chose, where a newline would forge a
// log line or a right-to-left override disguise a path.
func CleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || (unicode.IsGraphic(r) && !unicode.Is(unicode.Cf, r)) {
			return r
		}
		return '?'
	}, strings.ToValidUTF8(s, "?"))
}

// ConfigBool reads a boolean config key, or def when it is absent
func ConfigBool(cfg map[string]interface{}, key string, def bool) (bool, error) {
	raw, ok := cfg[key]
	if !ok || raw == nil {
		return def, nil
	}
	b, ok := raw.(bool)
	if !ok {
		return def, fmt.Errorf("%s must be true or false, got %v", key, raw)
	}
	return b, nil
}

// ConfigString reads a string config key, or def when it is absent or empty
func ConfigString(cfg map[string]interface{}, key, def string) (string, error) {
	raw, ok := cfg[key]
	if !ok || raw == nil {
		return def, nil
	}
	s, ok := raw.(string)
	if !ok {
		return def, fmt.Errorf("%s must be a string, got %v", key, raw)
	}
	if s == "" {
		return def, nil
	}
	return s, nil
}

// ConfigDuration reads a duration config key such as "48h", or def when it
// is absent. 0, "0" and "off" turn whatever it times off, as 0.
func ConfigDuration(cfg map[string]interface{}, key string, def time.Duration) (time.Duration, error) {
	raw, ok := cfg[key]
	if !ok || raw == nil {
		return def, nil
	}
	switch v := raw.(type) {
	case int:
		if v == 0 {
			return 0, nil
		}
	case string:
		if v == "0" || v == "off" {
			return 0, nil
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			return def, fmt.Errorf("%s: %w", key, err)
		}
		if d < 0 {
			return def, fmt.Errorf("%s must not be negative", key)
		}
		return d, nil
	}
	return def, fmt.Errorf("%s must be a duration such as \"48h\", or \"off\"; got %v", key, raw)
}

// ShortDuration formats d without trailing zero units: 48h, not 48h0m0s
func ShortDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

const (
	// maxScanAlerts is how many findings from one scan get an alert each;
	// the rest are summed up in one more
	maxScanAlerts = 5

	// maxQuoted is how many of a finding's lines an alert quotes
	maxQuoted = 5
)

// ScanReport turns the scans a scanner such as rkhunter or chkrootkit
// finishes into alerts, and alerts when it stops scanning. Not safe for
// concurrent use.
type ScanReport struct {
	SkillID   int
	SkillName string
	// Scanner names the tool in alert titles
	Scanner string
	// Location is where its results are, for alerts
	Location string
	Options  ReportOptions
	// MaxAge is how long without a scan finishing before alerting; 0 never
	MaxAge time.Duration
	// StaleHint says what to check when no scan has finished for MaxAge
	StaleHint string

	// prev is the last scan's findings, nil until a scan is seen
	prev    []Finding
	scanned bool
	// last is when the last scan finished, or when watching started
	last    time.Time
	started time.Time
	health  Deadman
}

// Start notes when watching started, which counts as a scan for MaxAge
func (r *ScanReport) Start(now time.Time) {
	r.started, r.last = now, now
}

// Scanned reports whether a scan has been seen
func (r *ScanReport) Scanned() bool { return r.scanned }

// Seed learns the scan already in the scanner's log when watching starts,
// finished at at. Its warnings are taken as known, so only what later scans
// add is reported; its infections are reported now.
func (r *ScanReport) Seed(findings []Finding, at time.Time) []notifier.Alert {
	found := Reportable(findings, findings, ReportOptions{Infections: r.Options.Infections})
	r.prev, r.scanned, r.last = findings, true, at
	return r.alerts(found, "in the last scan before fogbot started")
}

// Scan reports a scan that finished at at
func (r *ScanReport) Scan(findings []Finding, at time.Time) []notifier.Alert {
	var prev []Finding
	if r.scanned {
		prev = r.prev
	}
	found := Reportable(prev, findings, r.Options)
	unit := ""
	if !r.scanned {
		unit = "first scan fogbot has read"
	}
	r.prev, r.scanned, r.last = findings, true, at
	return r.alerts(found, unit)
}

func (r *ScanReport) alerts(found []Reported, unit string) []notifier.Alert {
	var out []notifier.Alert
	for i, f := range found {
		if i == maxScanAlerts {
			out = append(out, r.summary(found[i:]))
			break
		}
		out = append(out, r.alert(f, unit))
	}
	return out
}

func (r *ScanReport) alert(f Reported, unit string) notifier.Alert {
	title := r.Scanner + " Warning"
	if f.Infected {
		title = "Possible Rootkit (" + r.Scanner + ")"
	}
	if unit == "" {
		unit = "new since the last scan"
		if !f.New {
			unit = "also in the last scan"
		}
	}
	equip := r.Scanner
	if len(f.Lines) > 0 {
		equip = quoteLines(f.Lines)
	}
	check := trimText(CleanText(f.Check), 300)
	return notifier.Alert{
		Severity:  notifier.SeverityContact,
		SkillID:   r.SkillID,
		SkillName: r.SkillName,
		Title:     title,
		Size:      "1 finding",
		Activity:  check,
		Location:  r.Location,
		Unit:      unit,
		Time:      time.Now(),
		Equipment: equip,
		Metadata: map[string]string{
			"check":    check,
			"infected": strconv.FormatBool(f.Infected),
			"new":      strconv.FormatBool(f.New),
		},
	}
}

// summary is the one alert for the findings past maxScanAlerts
func (r *ScanReport) summary(rest []Reported) notifier.Alert {
	infected := false
	checks := make([]string, 0, len(rest))
	for _, f := range rest {
		infected = infected || f.Infected
		checks = append(checks, f.Check)
	}
	return notifier.Alert{
		Severity:  notifier.SeverityContact,
		SkillID:   r.SkillID,
		SkillName: r.SkillName,
		Title:     "More " + r.Scanner + " Findings",
		Size:      fmt.Sprintf("%d findings", len(rest)),
		Activity:  fmt.Sprintf("%d more findings in the same scan", len(rest)),
		Location:  r.Location,
		Unit:      "read the log for the rest",
		Time:      time.Now(),
		Equipment: quoteLines(checks),
		Metadata: map[string]string{
			"count":    strconv.Itoa(len(rest)),
			"infected": strconv.FormatBool(infected),
		},
	}
}

// CheckAge alerts when no scan has finished for MaxAge, and when one does
// again
func (r *ScanReport) CheckAge(now time.Time) (notifier.Alert, bool) {
	if r.MaxAge == 0 {
		return notifier.Alert{}, false
	}
	title := r.Scanner + " Not Scanning"
	if now.Sub(r.last) <= r.MaxAge {
		if r.health.Pass("stale") {
			return notifier.Alert{
				Severity:  notifier.SeverityNominal,
				SkillID:   r.SkillID,
				SkillName: r.SkillName,
				Title:     "[DEADMAN] Recovered: " + title,
				Activity:  r.Scanner + " has finished a scan again",
				Location:  r.Location,
				Time:      now,
				Equipment: "log",
			}, true
		}
		return notifier.Alert{}, false
	}
	if !r.health.Fail("stale") {
		return notifier.Alert{}, false
	}
	since := "no scan seen since fogbot started at " + r.started.Format("2006-01-02 15:04")
	if r.scanned {
		since = "last scan finished " + r.last.Format("2006-01-02 15:04")
	}
	return notifier.Alert{
		Severity:    notifier.SeverityContact,
		SkillID:     r.SkillID,
		SkillName:   r.SkillName,
		Title:       "[DEADMAN] " + title,
		Activity:    fmt.Sprintf("No %s scan has finished in %s", r.Scanner, ShortDuration(r.MaxAge)),
		Location:    r.Location,
		Unit:        since,
		Time:        now,
		Equipment:   r.StaleHint,
		Acknowledge: true,
	}, true
}

// quoteLines returns the first few lines for an alert
func quoteLines(lines []string) string {
	shown := lines
	if len(shown) > maxQuoted {
		shown = shown[:maxQuoted]
	}
	parts := make([]string, len(shown))
	for i, l := range shown {
		parts[i] = trimText(CleanText(l), 200)
	}
	s := strings.Join(parts, " | ")
	if more := len(lines) - len(shown); more > 0 {
		s += fmt.Sprintf(" (and %d more)", more)
	}
	return s
}

// trimText cuts s to n runes
func trimText(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}
