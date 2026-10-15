package sshmonitor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWatch_SurvivesRotation(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "auth.log")
	write := func(line string) {
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		f.WriteString(line + "\n")
	}
	write("Mar 15 12:00:00 host sshd[1]: Server listening")

	m := New()
	m.Configure(map[string]interface{}{"auth_log_path": logPath})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := m.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)

	expectRootLogin := func(ip string) {
		t.Helper()
		select {
		case a := <-ch:
			if !strings.Contains(a.Location, ip) {
				t.Fatalf("expected alert mentioning %s, got %+v", ip, a)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for alert from %s", ip)
		}
	}

	write("Mar 15 12:00:01 host sshd[2]: Accepted password for root from 10.0.0.1 port 22 ssh2")
	expectRootLogin("10.0.0.1")

	if err := os.Rename(logPath, logPath+".1"); err != nil {
		t.Fatal(err)
	}
	write("Mar 15 12:00:02 host sshd[3]: Accepted password for root from 10.0.0.2 port 22 ssh2")
	expectRootLogin("10.0.0.2")
}

