package sshmonitor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

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
}

var (
	// SSH login patterns
	acceptedPattern     = regexp.MustCompile(`Accepted (password|publickey) for (\S+) from ([\d.]+) port (\d+)`)
	failedPattern       = regexp.MustCompile(`Failed (password|publickey) for (\S+|invalid user \S+) from ([\d.]+)`)
	invalidUserPattern  = regexp.MustCompile(`Invalid user (\S+) from ([\d.]+)`)
	rootLoginPattern    = regexp.MustCompile(`Accepted .* for root from ([\d.]+)`)

	// sudo/su patterns
	sudoPattern         = regexp.MustCompile(`sudo:\s+(\S+) : TTY=(\S+) ; PWD=(\S+) ; USER=(\S+) ; COMMAND=(.+)`)
	sudoFailedPattern   = regexp.MustCompile(`sudo:\s+(\S+) : (\d+) incorrect password attempt`)
	suPattern           = regexp.MustCompile(`su\[(\d+)\]: pam_unix\(su:auth\): authentication failure.*logname=(\S+) uid=(\d+) .* ruser=(\S+) rhost=(\S*)  user=(\S+)`)
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
	}
}

func (s *SSHMonitor) ID() int         { return SkillID }
func (s *SSHMonitor) Name() string    { return SkillName }
func (s *SSHMonitor) Description() string {
	return "Monitors /var/log/auth.log for SSH authentication events"
}
func (s *SSHMonitor) Why() string {
	return "SSH is the most common remote access vector. Brute force and new-IP logins are high-value indicators."
}
func (s *SSHMonitor) Requires() []string { return []string{"auth.log read access"} }
func (s *SSHMonitor) Tags() []string     { return []string{"auth", "ssh", "brute-force"} }
func (s *SSHMonitor) DropIns() []skills.DropIn { return nil }
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

	// Allow custom auth log path (useful for testing)
	if path, ok := cfg["auth_log_path"].(string); ok {
		s.authLogPath = path
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

	// Open auth.log
	file, err := os.Open(s.authLogPath)
	if err != nil {
		log.Printf("[ssh-monitor] Failed to open %s: %v", s.authLogPath, err)
		return
	}
	defer file.Close()

	// Seek to end to only watch new entries
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		log.Printf("[ssh-monitor] Failed to seek to end: %v", err)
		return
	}

	reader := bufio.NewReader(file)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Printf("[ssh-monitor] Watching %s", s.authLogPath)

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			// Read new lines
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					if err == io.EOF {
						break // no more data right now
					}
					log.Printf("[ssh-monitor] Read error: %v", err)
					return
				}

				// Process the line
				s.processLine(line, alertChan)
			}

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
		if rootLoginPattern.MatchString(line) {
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
		ip := matches[3]

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
			// Extract target user if possible
			user := "unknown"
			if matches[2] != "" && !strings.HasPrefix(matches[2], "invalid") {
				user = matches[2]
			} else if m := invalidUserPattern.FindStringSubmatch(line); m != nil {
				user = m[1]
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
