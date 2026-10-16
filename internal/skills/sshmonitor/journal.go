package sshmonitor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
)

// Reading auth.log, fogbot can't tell who wrote a line: any local user can run
// `logger -p auth.info -t 'sshd[1]' "Accepted publickey for root from ..."`.
// That faked root login alerts, and a faked login from an address marked it
// known, so a later real login from it raised no new-IP alert.
//
// The journal records who sent each message in fields the sender can't set:
// _UID comes from the kernel with the message itself, and _EXE is read from
// /proc for the sending process. Messages are only believed when those fields
// say the program named in the message really sent it.

// journalArgs follows the auth and authpriv facilities, which is what auth.log
// receives, from now on
var journalArgs = []string{
	"--follow", "--lines=0", "--output=json",
	"--output-fields=MESSAGE,SYSLOG_IDENTIFIER,SYSLOG_PID,_PID,_UID,_EXE",
	"SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10",
}

// trustedExes are the binaries allowed to log as sudo and su. Both are setuid,
// so their messages carry the invoking user's _UID, and only the executable
// tells them apart from a user's own program that logs under the same name.
var trustedExes = map[string]map[string]bool{
	"sudo": {"/usr/bin/sudo": true, "/bin/sudo": true},
	"su":   {"/usr/bin/su": true, "/bin/su": true},
}

// watchJournal feeds trusted auth messages from the journal to processLine
// until ctx ends or journalctl exits
func (s *SSHMonitor) watchJournal(ctx context.Context, alertChan chan<- notifier.Alert) {
	cmd := exec.CommandContext(ctx, s.journalctl, journalArgs...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("[ssh-monitor] Failed to read the journal: %v", err)
		return
	}
	if err := cmd.Start(); err != nil {
		log.Printf("[ssh-monitor] Failed to start %s: %v", s.journalctl, err)
		return
	}
	log.Printf("[ssh-monitor] Watching the journal (auth and authpriv facilities)")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	lines := make(chan string)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line, ok := journalLine(sc.Bytes())
			if !ok {
				continue
			}
			select {
			case lines <- line:
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			cmd.Wait()
			return
		case line, ok := <-lines:
			if !ok {
				if err := cmd.Wait(); ctx.Err() == nil {
					log.Printf("[ssh-monitor] journalctl exited: %v", err)
				}
				return
			}
			s.processLine(line, alertChan)
		case <-ticker.C:
			s.cleanupFailures()
		}
	}
}

// journalLine turns a journal entry (journalctl -o json) into an auth.log
// style line for processLine, if it was sent by the program it names
func journalLine(data []byte) (string, bool) {
	var entry map[string]json.RawMessage
	if err := json.Unmarshal(data, &entry); err != nil {
		return "", false
	}
	ident, _ := journalField(entry, "SYSLOG_IDENTIFIER")
	msg, ok := journalField(entry, "MESSAGE")
	if !ok || !trustedSender(entry, ident) {
		return "", false
	}

	pid, ok := journalField(entry, "SYSLOG_PID")
	if !ok {
		pid, _ = journalField(entry, "_PID")
	}
	tag := ident
	if pid != "" {
		tag = fmt.Sprintf("%s[%s]", ident, pid)
	}
	// The timestamp and host only satisfy the patterns' syslog header
	return fmt.Sprintf("%s localhost %s: %s", time.Now().UTC().Format(time.RFC3339), tag, msg), true
}

// trustedSender reports whether the entry's sender may log as ident
func trustedSender(entry map[string]json.RawMessage, ident string) bool {
	switch ident {
	case "sshd", "sshd-session":
		// sshd logs as root. The kernel attaches the UID to the message, so
		// no other user can send one carrying _UID=0.
		uid, _ := journalField(entry, "_UID")
		return uid == "0"
	case "sudo", "su":
		// _EXE is missing when the sender exited before journald looked it up,
		// as sudo can right after logging a failure. A real alert matters more
		// than refusing the rare forgery that wins that race, so only an
		// executable that is known and wrong is refused.
		exe, ok := journalField(entry, "_EXE")
		return !ok || trustedExes[ident][exe]
	}
	return false
}

// journalField returns a single-valued field. journalctl writes a field that
// isn't valid UTF-8 as an array of bytes, and one with several values as an
// array of them; the latter is refused, since which value counts is unclear.
func journalField(entry map[string]json.RawMessage, name string) (string, bool) {
	raw, ok := entry[name]
	if !ok {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s, true
	}
	var b []byte
	var ints []int
	if json.Unmarshal(raw, &ints) == nil {
		for _, n := range ints {
			if n < 0 || n > 255 {
				return "", false
			}
			b = append(b, byte(n))
		}
		return string(b), true
	}
	return "", false
}
