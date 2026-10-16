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
