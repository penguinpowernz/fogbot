package sshmonitor

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/hpcloud/tail"
	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
)

const (
	SkillID   = 100
	SkillName = "ssh-monitor"
)

// SSHMonitor watches /var/log/auth.log for SSH authentication events
type SSHMonitor struct {
	mu                   sync.RWMutex
	enabled              bool
	config               map[string]interface{}
	bruteForceThreshold  int
	bruteForceWindow     time.Duration
	alertNewIPLogin      bool
	quietHoursExempt     bool
	knownIPs             map[string]bool // Track IPs we've seen before
	failuresByIP         map[string][]time.Time
	authLogPath          string

	// source is where auth events are read from: "journal" (the default),
	// which records who sent each message, or "file", the auth.log text,
	// which any local user can write fake lines to
	source     string
	journalctl string // the journalctl binary
}

// ipPattern matches IPv4 and IPv6 addresses (sshd logs IPv6 unbracketed, e.g. 2001:db8::1)
const ipPattern = `[0-9A-Fa-f:.]+`

// syslogHeader matches the timestamp and hostname that start every auth.log
// line, in both traditional ("Apr  6 10:00:01 host") and RFC 3339 formats.
//
// Every pattern is anchored to it and to the program tag. An unauthenticated
// client controls the username sshd logs, so an unanchored pattern would let a
// login attempt as user "Accepted password for root from 1.2.3.4 port 22" fake
// a root login alert, or mark an IP as known so a later real login from it
// raises no new-IP alert.
const syslogHeader = `^(?:[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+) \S+ `

// sshdTag matches sshd's program tag (sshd-session on OpenSSH 9.8+)
const sshdTag = `sshd(?:-session)?\[\d+\]: `

var (
	// SSH login patterns
	acceptedPattern = regexp.MustCompile(syslogHeader + sshdTag + `Accepted (\S+) for (\S+) from (` + ipPattern + `) port (\d+)`)
	// The attempted username may contain spaces and even " from <ip> port <n>",
	// so take the address from the end of the line: the greedy user group leaves
	// only sshd's own trailing " from <ip> port <n> ssh2[: key info]"
	failedPattern = regexp.MustCompile(syslogHeader + sshdTag + `Failed (\S+) for (invalid user )?(.*) from (` + ipPattern + `) port \d+(?: ssh2)?(?::.*)?$`)

	// sudo/su patterns
	sudoPattern       = regexp.MustCompile(syslogHeader + `sudo(?:\[\d+\])?:\s+(\S+) : TTY=(\S+) ; PWD=(\S+) ; USER=(\S+) ; COMMAND=(.+)`)
	sudoFailedPattern = regexp.MustCompile(syslogHeader + `sudo(?:\[\d+\])?:\s+(\S+) : (\d+) incorrect password attempt`)
	suPattern         = regexp.MustCompile(syslogHeader + `su\[(\d+)\]: pam_unix\(su:auth\): authentication failure.*logname=(\S+) uid=(\d+) .* ruser=(\S+) rhost=(\S*)  user=(\S+)`)
)

// New creates a new SSHMonitor skill
func New() *SSHMonitor {
	return &SSHMonitor{
		enabled:             false,
		knownIPs:            make(map[string]bool),
		failuresByIP:        make(map[string][]time.Time),
		bruteForceThreshold: 5,
		bruteForceWindow:    60 * time.Second,
		alertNewIPLogin:     true,
		quietHoursExempt:    false,
		authLogPath:         "/var/log/auth.log",
		source:              "journal",
		journalctl:          "journalctl",
	}
}

func (s *SSHMonitor) ID() int         { return SkillID }
func (s *SSHMonitor) Name() string    { return SkillName }
func (s *SSHMonitor) Description() string {
	return "Monitors the systemd journal's auth messages for SSH authentication events"
}
func (s *SSHMonitor) Why() string {
	return "SSH is the most common remote access vector. Brute force and new-IP logins are high-value indicators."
}
func (s *SSHMonitor) Requires() []string { return []string{"systemd journal read access"} }
func (s *SSHMonitor) Tags() []string     { return []string{"auth", "ssh", "brute-force"} }
func (s *SSHMonitor) DropIns() []skills.DropIn    { return nil }
func (s *SSHMonitor) SetupHints() []string        { return nil }
func (s *SSHMonitor) Enabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled
}

func (s *SSHMonitor) SetEnabled(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = enabled
}

func (s *SSHMonitor) Config() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

func (s *SSHMonitor) Configure(cfg map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.config = cfg

	// Parse config
	if threshold, ok := cfg["brute_force_threshold"].(int); ok {
		s.bruteForceThreshold = threshold
	}

	if windowStr, ok := cfg["brute_force_window"].(string); ok {
		if d, err := time.ParseDuration(windowStr); err == nil {
			s.bruteForceWindow = d
		}
	}

	if alert, ok := cfg["alert_new_ip_login"].(bool); ok {
		s.alertNewIPLogin = alert
	}

	if exempt, ok := cfg["quiet_hours_exempt"].(bool); ok {
		s.quietHoursExempt = exempt
	}

	// Setting auth_log_path reads that file, as before the journal was used
	s.source = "journal"
	if path, ok := cfg["auth_log_path"].(string); ok {
		s.authLogPath = path
		s.source = "file"
	}
	if source, ok := cfg["log_source"].(string); ok {
		if source != "journal" && source != "file" {
			return fmt.Errorf("invalid log_source %q: use journal or file", source)
		}
		s.source = source
	}

	return nil
}

func (s *SSHMonitor) Watch(ctx context.Context) (<-chan notifier.Alert, error) {
	alertChan := make(chan notifier.Alert, 10)

	go s.watchLoop(ctx, alertChan)

	return alertChan, nil
}

func (s *SSHMonitor) watchLoop(ctx context.Context, alertChan chan<- notifier.Alert) {
	defer close(alertChan)

	if s.source == "journal" {
		s.watchJournal(ctx, alertChan)
		return
	}
	log.Printf("[ssh-monitor] Reading %s: its lines can't be traced to their sender, so local users can fake events (log_source: journal can)", s.authLogPath)

	// Follow from the end of the file. ReOpen handles rotation and truncation by
	// reading the replacement file from the start, and waits if the file is missing.
	cfg := tail.Config{Follow: true, ReOpen: true, Logger: tail.DiscardingLogger}
	if _, err := os.Stat(s.authLogPath); err == nil {
		// Only skip existing content; a file created later is read from the start
		cfg.Location = &tail.SeekInfo{Offset: 0, Whence: io.SeekEnd}
	}
	t, err := tail.TailFile(s.authLogPath, cfg)
	if err != nil {
		log.Printf("[ssh-monitor] Failed to tail %s: %v", s.authLogPath, err)
		return
	}
	defer t.Cleanup()
	defer t.Stop()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Printf("[ssh-monitor] Watching %s", s.authLogPath)

	for {
		select {
		case <-ctx.Done():
			return

		case line, ok := <-t.Lines:
			if !ok {
				log.Printf("[ssh-monitor] Tail of %s stopped: %v", s.authLogPath, t.Err())
				return
			}
			if line.Err != nil {
				log.Printf("[ssh-monitor] Read error: %v", line.Err)
				continue
			}
			s.processLine(line.Text, alertChan)

		case <-ticker.C:
			// Clean up old failure timestamps
			s.cleanupFailures()
		}
	}
}

func (s *SSHMonitor) processLine(line string, alertChan chan<- notifier.Alert) {
	now := time.Now()

	// Check for successful logins
	if matches := acceptedPattern.FindStringSubmatch(line); matches != nil {
		method := matches[1]
		user := matches[2]
		ip := matches[3]
		port := matches[4]

		// Check if this is a root login
		if user == "root" {
			alertChan <- notifier.Alert{
				Severity:  notifier.SeverityContact,
				SkillID:   SkillID,
				SkillName: SkillName,
				Title:     "Direct Root Login",
				Size:      "1 connection",
				Activity:  fmt.Sprintf("Root login via %s", method),
				Location:  fmt.Sprintf("from %s:%s", ip, port),
				Unit:      "user=root",
				Time:      now,
				Equipment: method,
				Acknowledge: true,
			}
			return
		}

		// Check if this is a new IP
		s.mu.Lock()
		isNewIP := !s.knownIPs[ip]
		s.knownIPs[ip] = true
		s.mu.Unlock()

		if isNewIP && s.alertNewIPLogin {
			alertChan <- notifier.Alert{
				Severity:  notifier.SeverityContact,
				SkillID:   SkillID,
				SkillName: SkillName,
				Title:     "SSH Login from New IP",
				Size:      "1 connection",
				Activity:  fmt.Sprintf("Successful login for user %s", user),
				Location:  fmt.Sprintf("from %s:%s", ip, port),
				Unit:      fmt.Sprintf("user=%s", user),
				Time:      now,
				Equipment: method,
				Acknowledge: true,
			}
		}

		return
	}

	// Check for failed logins
	if matches := failedPattern.FindStringSubmatch(line); matches != nil {
		ip := matches[4]

		s.mu.Lock()
		s.failuresByIP[ip] = append(s.failuresByIP[ip], now)
		failures := s.failuresByIP[ip]
		s.mu.Unlock()

		// Count failures within the window
		cutoff := now.Add(-s.bruteForceWindow)
		count := 0
		for _, t := range failures {
			if t.After(cutoff) {
				count++
			}
		}

		// Alert if threshold exceeded
		if count >= s.bruteForceThreshold {
			user := matches[3]
			if matches[2] != "" {
				user += " (invalid)"
			}

			alertChan <- notifier.Alert{
				Severity:  notifier.SeverityMovement,
				SkillID:   SkillID,
				SkillName: SkillName,
				Title:     "SSH Brute Force",
				Size:      fmt.Sprintf("%d attempts", count),
				Activity:  "Failed SSH authentication attempts",
				Location:  fmt.Sprintf("from %s", ip),
				Unit:      fmt.Sprintf("targeting user: %s", user),
				Time:      now,
				Equipment: fmt.Sprintf("window: %v", s.bruteForceWindow),
			}

			// Reset this IP's failures to avoid spam
			s.mu.Lock()
			s.failuresByIP[ip] = []time.Time{}
			s.mu.Unlock()
		}

		return
	}

	// Check for sudo usage
	if matches := sudoPattern.FindStringSubmatch(line); matches != nil {
		user := matches[1]
		command := matches[5]

		log.Printf("[ssh-monitor] sudo: %s ran: %s", user, command)
		// Could add sudo alerts here if desired
		return
	}

	// Check for failed sudo
	if matches := sudoFailedPattern.FindStringSubmatch(line); matches != nil {
		user := matches[1]
		attempts := matches[2]

		alertChan <- notifier.Alert{
			Severity:  notifier.SeverityMovement,
			SkillID:   SkillID,
			SkillName: SkillName,
			Title:     "Failed Sudo Attempt",
			Size:      fmt.Sprintf("%s attempts", attempts),
			Activity:  "Incorrect sudo password",
			Location:  "local",
			Unit:      fmt.Sprintf("user=%s", user),
			Time:      now,
			Equipment: "sudo",
		}
		return
	}

	// Check for su failures
	if matches := suPattern.FindStringSubmatch(line); matches != nil {
		sourceUser := matches[4]
		targetUser := matches[6]

		alertChan <- notifier.Alert{
			Severity:  notifier.SeverityMovement,
			SkillID:   SkillID,
			SkillName: SkillName,
			Title:     "Failed su Attempt",
			Size:      "1 attempt",
			Activity:  "su authentication failure",
			Location:  "local",
			Unit:      fmt.Sprintf("%s → %s", sourceUser, targetUser),
			Time:      now,
			Equipment: "su",
		}
		return
	}
}

func (s *SSHMonitor) cleanupFailures() {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-s.bruteForceWindow * 2) // keep 2x window for safety

	for ip, failures := range s.failuresByIP {
		kept := make([]time.Time, 0)
		for _, t := range failures {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}

		if len(kept) == 0 {
			delete(s.failuresByIP, ip)
		} else {
			s.failuresByIP[ip] = kept
		}
	}
}


// DeduceCommands - stub for legacy skill
func (s *SSHMonitor) DeduceCommands(cfg map[string]interface{}) ([]skills.SystemCommand, error) {
	return []skills.SystemCommand{}, nil
}

// CheckSystemState - stub for legacy skill
func (s *SSHMonitor) CheckSystemState() (bool, error) {
	return true, nil
}
