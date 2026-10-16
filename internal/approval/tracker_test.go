package approval

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/penguinpowernz/fogbot/internal/skills"
)

// A stored hash that doesn't match the stored command must not approve the
// command it was computed from
func TestLoad_RecomputesHashes(t *testing.T) {
	dir := t.TempDir()
	entries := []ApprovedCommand{{
		SkillID: 510,
		Command: "iptables -A INPUT -j ACCEPT",
		Hash:    hashCommand(510, "iptables -A INPUT -p tcp --dport 23 -j LOG"),
	}}
	data, _ := json.Marshal(entries)
	if err := os.WriteFile(filepath.Join(dir, "approved-commands.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	tr, err := NewTracker(dir)
	if err != nil {
		t.Fatal(err)
	}
	if tr.IsApproved(510, "iptables -A INPUT -p tcp --dport 23 -j LOG") {
		t.Error("command approved via a mismatched stored hash")
	}
	if !tr.IsApproved(510, "iptables -A INPUT -j ACCEPT") {
		t.Error("recorded command should be approved")
	}
}

// Revocations made by another process are seen after Reload
func TestReload_PicksUpRevocations(t *testing.T) {
	dir := t.TempDir()
	daemon, err := NewTracker(dir)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := NewTracker(dir)
	if err != nil {
		t.Fatal(err)
	}

	cmd := skills.SystemCommand{Command: "auditctl -w /etc/shadow -p rwa -k fb-file-500"}
	if err := cli.Approve(500, "file-watch", cmd); err != nil {
		t.Fatal(err)
	}
	if err := daemon.Reload(); err != nil {
		t.Fatal(err)
	}
	if !daemon.IsApproved(500, cmd.Command) {
		t.Fatal("approval not picked up on reload")
	}

	if err := cli.RevokeSkill(500); err != nil {
		t.Fatal(err)
	}
	if err := daemon.Reload(); err != nil {
		t.Fatal(err)
	}
	if daemon.IsApproved(500, cmd.Command) {
		t.Fatal("revoked approval still honoured after reload")
	}
}
