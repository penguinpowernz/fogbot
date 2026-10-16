package skills

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeSkill struct {
	Skill // unimplemented methods panic if called
	cmds  []SystemCommand
	ok    bool
}

func (f *fakeSkill) ID() int                         { return 900 }
func (f *fakeSkill) Name() string                    { return "fake" }
func (f *fakeSkill) Enabled() bool                   { return true }
func (f *fakeSkill) Config() map[string]interface{}  { return nil }
func (f *fakeSkill) CheckSystemState() (bool, error) { return f.ok, nil }
func (f *fakeSkill) DeduceCommands(map[string]interface{}) ([]SystemCommand, error) {
	return f.cmds, nil
}

type fakeTracker struct {
	ApprovalTracker
	approved map[string]bool
}

func (f *fakeTracker) IsApproved(_ int, cmd string) bool { return f.approved[cmd] }

func appendCmds(out string, names ...string) []SystemCommand {
	var cmds []SystemCommand
	for _, n := range names {
		cmds = append(cmds, SystemCommand{Command: fmt.Sprintf(`sh -c "echo %s >> %s"`, n, out)})
	}
	return cmds
}

func readRan(t *testing.T, out string) string {
	data, _ := os.ReadFile(out)
	return strings.Join(strings.Fields(string(data)), " ")
}

func TestReapplyOnStartup_RunsApprovedCommandsInDeducedOrder(t *testing.T) {
	out := filepath.Join(t.TempDir(), "ran")
	cmds := appendCmds(out, "first", "second", "third")
	tracker := &fakeTracker{approved: map[string]bool{}}
	for _, c := range cmds {
		tracker.approved[c.Command] = true
	}

	if err := NewEnabler(tracker).ReapplyOnStartup(&fakeSkill{cmds: cmds}); err != nil {
		t.Fatal(err)
	}
	if got := readRan(t, out); got != "first second third" {
		t.Fatalf("expected commands in deduced order, got %q", got)
	}
}

func TestReapplyOnStartup_SkipsUnapprovedAndReportsIt(t *testing.T) {
	out := filepath.Join(t.TempDir(), "ran")
	cmds := appendCmds(out, "approved", "changed")
	tracker := &fakeTracker{approved: map[string]bool{cmds[0].Command: true}}

	err := NewEnabler(tracker).ReapplyOnStartup(&fakeSkill{cmds: cmds})
	if err == nil {
		t.Fatal("expected an error reporting the partial repair")
	}
	if got := readRan(t, out); got != "approved" {
		t.Fatalf("expected only the approved command to run, got %q", got)
	}
}

func TestReapplyOnStartup_NothingApproved(t *testing.T) {
	out := filepath.Join(t.TempDir(), "ran")
	err := NewEnabler(&fakeTracker{}).ReapplyOnStartup(&fakeSkill{cmds: appendCmds(out, "x")})
	if err == nil || readRan(t, out) != "" {
		t.Fatalf("expected an error and nothing run, got err=%v ran=%q", err, readRan(t, out))
	}
}

func TestReapplyOnStartup_AlreadyConfigured(t *testing.T) {
	out := filepath.Join(t.TempDir(), "ran")
	if err := NewEnabler(&fakeTracker{}).ReapplyOnStartup(&fakeSkill{cmds: appendCmds(out, "x"), ok: true}); err != nil {
		t.Fatal(err)
	}
	if readRan(t, out) != "" {
		t.Fatal("nothing should run when the system is already configured")
	}
}

func TestExecuteCommand_DryRunDoesNotRun(t *testing.T) {
	out := filepath.Join(t.TempDir(), "ran")
	e := NewEnabler(&fakeTracker{})
	e.SetDryRun(true)

	if err := e.executeCommand(appendCmds(out, "x")[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("dry-run executed the command")
	}
}

// promptSkill adds what the approval prompt needs to fakeSkill
type promptSkill struct{ fakeSkill }

func (*promptSkill) Why() string            { return "" }
func (*promptSkill) SetupHints() []string   { return nil }
func (*promptSkill) SetEnabled(enabled bool) {}

func withStdin(t *testing.T, input string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.WriteString(input)
	w.Close()
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old; r.Close() })
}

// Enable has no way to skip the prompt: a skill YAML without
// requires_approval must not get its commands run unasked
func TestEnable_DeclinedApprovalRunsNothing(t *testing.T) {
	out := filepath.Join(t.TempDir(), "ran")
	withStdin(t, "n\n")

	err := NewEnabler(&fakeTracker{}).Enable(&promptSkill{fakeSkill{cmds: appendCmds(out, "x")}})
	if err == nil {
		t.Fatal("expected an error when approval is declined")
	}
	if readRan(t, out) != "" {
		t.Fatal("a command ran without approval")
	}
}

// recordingTracker keeps approvals in memory
type recordingTracker struct {
	ApprovalTracker
	approved map[string]bool
	revoked  bool
}

func (r *recordingTracker) IsApproved(_ int, cmd string) bool { return r.approved[cmd] }
func (r *recordingTracker) Approve(_ int, _ string, cmd CommandInfo) error {
	r.approved[cmd.GetCommand()] = true
	return nil
}
func (r *recordingTracker) RevokeSkill(int) error {
	r.approved = map[string]bool{}
	r.revoked = true
	return nil
}

// Rules left behind by an earlier install (or added by hand) were never
// approved, so startup repair couldn't restore them after a reboot
func TestEnable_AlreadyConfiguredRecordsApprovalWithoutRunning(t *testing.T) {
	out := filepath.Join(t.TempDir(), "ran")
	cmds := appendCmds(out, "x", "y")
	tracker := &recordingTracker{approved: map[string]bool{}}
	withStdin(t, "y\n")

	if err := NewEnabler(tracker).Enable(&promptSkill{fakeSkill{cmds: cmds, ok: true}}); err != nil {
		t.Fatal(err)
	}
	if readRan(t, out) != "" {
		t.Fatal("commands ran although the configuration was already in place")
	}
	for _, c := range cmds {
		if !tracker.approved[c.Command] {
			t.Fatalf("%q not approved, so startup repair couldn't restore it", c.Command)
		}
	}
}

func TestEnable_AlreadyConfiguredAndApprovedDoesNotPrompt(t *testing.T) {
	cmds := appendCmds(filepath.Join(t.TempDir(), "ran"), "x")
	tracker := &recordingTracker{approved: map[string]bool{cmds[0].Command: true}}
	withStdin(t, "") // a prompt would fail reading stdin

	if err := NewEnabler(tracker).Enable(&promptSkill{fakeSkill{cmds: cmds, ok: true}}); err != nil {
		t.Fatal(err)
	}
}

// setupSkill only deduces what is missing, like port-tripwires
type setupSkill struct {
	promptSkill
	setup []SystemCommand
}

func (s *setupSkill) SetupCommands(map[string]interface{}) ([]SystemCommand, error) {
	return s.setup, nil
}

func TestEnable_AlreadyConfiguredApprovesSetupCommands(t *testing.T) {
	setup := appendCmds(filepath.Join(t.TempDir(), "ran"), "add")
	tracker := &recordingTracker{approved: map[string]bool{}}
	withStdin(t, "y\n")

	skill := &setupSkill{promptSkill: promptSkill{fakeSkill{ok: true}}, setup: setup}
	if err := NewEnabler(tracker).Enable(skill); err != nil {
		t.Fatal(err)
	}
	if !tracker.approved[setup[0].Command] {
		t.Fatal("setup command not approved")
	}
}

// teardownSkill removes what it put in place
type teardownSkill struct {
	promptSkill
	teardown []SystemCommand
}

func (s *teardownSkill) TeardownCommands() ([]SystemCommand, error) { return s.teardown, nil }

func TestDisable_RemovesConfigThenRevokes(t *testing.T) {
	out := filepath.Join(t.TempDir(), "ran")
	tracker := &recordingTracker{approved: map[string]bool{"add": true}}
	withStdin(t, "y\n")

	skill := &teardownSkill{teardown: appendCmds(out, "remove")}
	if err := NewEnabler(tracker).Disable(skill); err != nil {
		t.Fatal(err)
	}
	if readRan(t, out) != "remove" {
		t.Fatalf("teardown didn't run, ran %q", readRan(t, out))
	}
	if !tracker.revoked {
		t.Fatal("approvals not revoked")
	}
	if tracker.approved["remove"] {
		t.Fatal("teardown commands must not be recorded for startup repair")
	}
}

func TestDisable_DeclinedLeavesEverything(t *testing.T) {
	out := filepath.Join(t.TempDir(), "ran")
	tracker := &recordingTracker{approved: map[string]bool{"add": true}}
	withStdin(t, "n\n")

	skill := &teardownSkill{teardown: appendCmds(out, "remove")}
	if err := NewEnabler(tracker).Disable(skill); err == nil {
		t.Fatal("expected an error when teardown is declined")
	}
	if readRan(t, out) != "" || tracker.revoked {
		t.Fatal("declined disable changed something")
	}
}

func TestDisable_NothingToRemoveDoesNotPrompt(t *testing.T) {
	tracker := &recordingTracker{approved: map[string]bool{}}
	withStdin(t, "")

	if err := NewEnabler(tracker).Disable(&teardownSkill{}); err != nil {
		t.Fatal(err)
	}
	if !tracker.revoked {
		t.Fatal("approvals not revoked")
	}
}
