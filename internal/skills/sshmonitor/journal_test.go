package sshmonitor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
)

// Entries as journalctl -o json prints them. forgedRoot is what
// `logger -p auth.info -t 'sshd[4242]' "Accepted ..."` run by uid 1000 gives.
const (
	realRoot   = `{"SYSLOG_IDENTIFIER":"sshd","SYSLOG_PID":"811","_PID":"811","_UID":"0","_EXE":"/usr/sbin/sshd","MESSAGE":"Accepted publickey for root from 203.0.113.9 port 50122 ssh2: ED25519 SHA256:abc"}`
	forgedRoot = `{"SYSLOG_IDENTIFIER":"sshd","SYSLOG_PID":"4242","_PID":"5120","_UID":"1000","_COMM":"logger","MESSAGE":"Accepted publickey for root from 203.0.113.250 port 22 ssh2"}`
)

func TestJournalLine_TrustsOnlyRealSenders(t *testing.T) {
	for name, tc := range map[string]struct {
		entry string
		want  bool
	}{
		"sshd as root":                   {realRoot, true},
		"sshd as root, exe already gone": {`{"SYSLOG_IDENTIFIER":"sshd","SYSLOG_PID":"9","_UID":"0","MESSAGE":"Failed password for bob from 203.0.113.9 port 1 ssh2"}`, true},
		"sshd-session as root":           {`{"SYSLOG_IDENTIFIER":"sshd-session","SYSLOG_PID":"9","_UID":"0","_EXE":"/usr/lib/openssh/sshd-session","MESSAGE":"x"}`, true},
		"logger posing as sshd":          {forgedRoot, false},
		"own sshd run by a user":         {`{"SYSLOG_IDENTIFIER":"sshd","SYSLOG_PID":"9","_UID":"1000","_EXE":"/usr/sbin/sshd","MESSAGE":"x"}`, false},
		"sshd with no sender uid":        {`{"SYSLOG_IDENTIFIER":"sshd","MESSAGE":"x"}`, false},
		"real sudo, invoking user's uid": {`{"SYSLOG_IDENTIFIER":"sudo","_UID":"1000","_EXE":"/usr/bin/sudo","MESSAGE":"x"}`, true},
		"sudo, exe already gone":         {`{"SYSLOG_IDENTIFIER":"sudo","_UID":"1000","MESSAGE":"x"}`, true},
		"logger posing as sudo":          {`{"SYSLOG_IDENTIFIER":"sudo","_UID":"1000","_EXE":"/usr/bin/logger","MESSAGE":"x"}`, false},
		"copied binary named su":         {`{"SYSLOG_IDENTIFIER":"su","_UID":"1000","_EXE":"/tmp/su","MESSAGE":"x"}`, false},
		"other program":                  {`{"SYSLOG_IDENTIFIER":"CRON","_UID":"0","_EXE":"/usr/sbin/cron","MESSAGE":"x"}`, false},
		"two values for _UID":            {`{"SYSLOG_IDENTIFIER":"sshd","_UID":["1000","0"],"MESSAGE":"x"}`, false},
		"not json":                       {`Accepted publickey for root`, false},
	} {
		if _, got := journalLine([]byte(tc.entry)); got != tc.want {
			t.Errorf("%s: trusted=%v, want %v", name, got, tc.want)
		}
	}
}

func TestJournalLine_MatchesPatterns(t *testing.T) {
	m := New()
	ch := make(chan notifier.Alert, 4)
	for _, entry := range []string{
		realRoot,
		// A message that isn't valid UTF-8 comes as an array of bytes
		`{"SYSLOG_IDENTIFIER":"sudo","SYSLOG_PID":"77","_EXE":"/usr/bin/sudo","MESSAGE":[32,32,32,98,111,98,32,58,32,51,32,105,110,99,111,114,114,101,99,116,32,112,97,115,115,119,111,114,100,32,97,116,116,101,109,112,116,115]}`,
	} {
		line, ok := journalLine([]byte(entry))
		if !ok {
			t.Fatalf("entry not trusted: %s", entry)
		}
		m.processLine(line, ch)
	}
	if len(ch) != 2 {
		t.Fatalf("expected a root login and a failed sudo alert, got %d", len(ch))
	}
	if a := <-ch; a.Title != "Direct Root Login" {
		t.Fatalf("unexpected alert %+v", a)
	}
	if a := <-ch; a.Title != "Failed Sudo Attempt" {
		t.Fatalf("unexpected alert %+v", a)
	}
}

// End to end against a stand-in journalctl: the forged login is ignored and
// doesn't mark its address known; the real one alerts
func TestWatchJournal_IgnoresForgedLines(t *testing.T) {
	dir := t.TempDir()
	entries := filepath.Join(dir, "entries")
	os.WriteFile(entries, []byte(forgedRoot+"\n"+realRoot+"\n"), 0600)
	fake := filepath.Join(dir, "journalctl")
	os.WriteFile(fake, []byte("#!/bin/sh\ncat "+entries+"\nexec sleep 60\n"), 0700)

	m := New()
	m.journalctl = fake
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, _ := m.Watch(ctx)

	select {
	case a := <-ch:
		if a.Title != "Direct Root Login" || a.Location != "from 203.0.113.9:50122" {
			t.Fatalf("unexpected alert %+v", a)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no alert for the real login")
	}
	select {
	case a := <-ch:
		t.Fatalf("forged line raised %+v", a)
	case <-time.After(200 * time.Millisecond):
	}

	cancel()
	select {
	case _, ok := <-ch:
		for ok {
			_, ok = <-ch
		}
	case <-time.After(3 * time.Second):
		t.Fatal("watcher didn't stop with its context")
	}
}

func TestConfigure_LogSource(t *testing.T) {
	m := New()
	if m.Configure(map[string]interface{}{}); m.source != "journal" {
		t.Fatalf("default source %q, want journal", m.source)
	}
	if m.Configure(map[string]interface{}{"auth_log_path": "/x"}); m.source != "file" {
		t.Fatalf("auth_log_path should read the file, got %q", m.source)
	}
	if err := m.Configure(map[string]interface{}{"log_source": "syslog"}); err == nil {
		t.Fatal("expected an error for an unknown log_source")
	}
	m.Configure(shippedConfig(t))
	if m.source != "journal" {
		t.Fatalf("shipped YAML source %q, want journal", m.source)
	}
}
