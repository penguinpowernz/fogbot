package skills

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/kballard/go-shellquote"
)

// Enabler handles the process of enabling skills with user approval
type Enabler struct {
	approvalTracker ApprovalTracker

	// dryRun prints commands instead of running them
	dryRun bool
}

// CommandInfo interface for commands that can be approved
type CommandInfo interface {
	GetCommand() string
	GetDescription() string
	GetMetadata() map[string]string
}

// ApprovalTracker interface for tracking approved commands
type ApprovalTracker interface {
	Approve(skillID int, skillName string, cmd CommandInfo) error
	IsApproved(skillID int, command string) bool
	GetApprovedCommands(skillID int) []ApprovedCommand
	RevokeSkill(skillID int) error
}

// ApprovedCommand represents a previously approved command
type ApprovedCommand struct {
	SkillID     int
	SkillName   string
	Command     string
	Description string
	Metadata    map[string]string
}

// SetupCommander is implemented by skills whose DeduceCommands only returns
// what is missing from the system. SetupCommands returns every command that
// sets the skill up from nothing, which is what startup repair needs approved.
type SetupCommander interface {
	SetupCommands(cfg map[string]interface{}) ([]SystemCommand, error)
}

// Teardowner is implemented by skills that change the system. TeardownCommands
// returns the commands that remove what the skill put in place, as found on
// the system now.
type Teardowner interface {
	TeardownCommands() ([]SystemCommand, error)
}

// setupCommands returns every command that sets skill up from nothing
func setupCommands(skill Skill) ([]SystemCommand, error) {
	if s, ok := skill.(SetupCommander); ok {
		return s.SetupCommands(skill.Config())
	}
	return skill.DeduceCommands(skill.Config())
}

// NewEnabler creates a new skill enabler
func NewEnabler(tracker ApprovalTracker) *Enabler {
	return &Enabler{
		approvalTracker: tracker,
	}
}

// Enable handles the full enablement workflow for a skill. Every system command
// needs the user's approval: a skill YAML that set requires_approval to false
// (or left it out) would otherwise run commands unprompted, and unrecorded
// commands could never be restored by startup repair.
func (e *Enabler) Enable(skill Skill) error {
	// Step 1: Check if system is already configured
	isConfigured, err := skill.CheckSystemState()
	if err != nil {
		if !e.dryRun {
			return fmt.Errorf("failed to check system state: %w", err)
		}
		// Dry-run usually runs unprivileged, where the check can't work
		fmt.Printf("  [dry-run] Could not check system state (%v), assuming not configured\n", err)
	}

	if isConfigured {
		fmt.Printf("✓ Skill '%s' configuration already exists in system\n", skill.Name())
		// Startup repair only runs approved commands. Rules left by an earlier
		// install, or added by hand, were never approved, so without this they
		// could not be restored after a reboot or an auditd restart.
		if err := e.approveExisting(skill); err != nil {
			return fmt.Errorf("approval denied or failed: %w", err)
		}
		skill.SetEnabled(true)
		return nil
	}

	// Step 2: Deduce commands from config
	commands, err := skill.DeduceCommands(skill.Config())
	if err != nil {
		return fmt.Errorf("failed to deduce commands: %w", err)
	}

	if len(commands) == 0 {
		// No commands needed, just enable
		skill.SetEnabled(true)
		return nil
	}

	// Step 3: Filter out already-approved commands from the approval prompt
	needsApproval := []SystemCommand{}
	for _, cmd := range commands {
		if !e.approvalTracker.IsApproved(skill.ID(), cmd.Command) {
			needsApproval = append(needsApproval, cmd)
		}
	}

	// Step 4: Request approval if needed
	if len(needsApproval) > 0 {
		if err := e.requestApproval(skill, needsApproval, false); err != nil {
			return fmt.Errorf("approval denied or failed: %w", err)
		}
	}

	// Step 5: Print setup hints if the skill has any (e.g. create canary files)
	if hints := skill.SetupHints(); len(hints) > 0 {
		fmt.Printf("\n%s%s┌─────────────────────────────────────────────────────────────────┐%s\n", colorBold, colorCyan, colorReset)
		fmt.Printf("%s%s│ ℹ  Optional: create missing canary/bait files%s\n", colorBold, colorCyan, colorReset)
		fmt.Printf("%s%s└─────────────────────────────────────────────────────────────────┘%s\n", colorBold, colorCyan, colorReset)
		fmt.Printf("%sRun these commands if you want to create files that don't exist yet:%s\n\n", colorGray, colorReset)
		for _, hint := range hints {
			fmt.Printf("  %s%s%s\n", colorGreen, hint, colorReset)
		}
		fmt.Println()
	}

	// Step 6: Execute all commands. CheckSystemState already confirmed the system
	// is not configured, so every command needs to run regardless of prior approval.
	fmt.Printf("\nApplying configuration for skill '%s'...\n", skill.Name())
	for _, cmd := range commands {
		if err := e.executeCommand(cmd); err != nil {
			return fmt.Errorf("failed to execute command: %w", err)
		}
	}

	skill.SetEnabled(true)
	fmt.Printf("✓ Skill '%s' enabled successfully\n\n", skill.Name())
	return nil
}

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
)

// approveExisting asks for approval of the commands that set skill up, when
// its configuration is already on the system but not all of them are approved
func (e *Enabler) approveExisting(skill Skill) error {
	commands, err := setupCommands(skill)
	if err != nil {
		return fmt.Errorf("failed to deduce commands: %w", err)
	}
	var needsApproval []SystemCommand
	for _, cmd := range commands {
		if !e.approvalTracker.IsApproved(skill.ID(), cmd.Command) {
			needsApproval = append(needsApproval, cmd)
		}
	}
	if len(needsApproval) == 0 {
		return nil
	}
	return e.requestApproval(skill, needsApproval, true)
}

// requestApproval presents commands to user and requests approval. With
// inPlace the configuration already exists, so the commands are only approved
// for startup repair, not run now.
func (e *Enabler) requestApproval(skill Skill, commands []SystemCommand, inPlace bool) error {
	fmt.Printf("\n%s%s┌─────────────────────────────────────────────────────────────────┐%s\n", colorBold, colorYellow, colorReset)
	fmt.Printf("%s%s│ ⚠  Skill '%s' requires system configuration%s\n", colorBold, colorYellow, skill.Name(), colorReset)
	fmt.Printf("%s%s└─────────────────────────────────────────────────────────────────┘%s\n\n", colorBold, colorYellow, colorReset)

	fmt.Printf("%s%sWhy this skill matters:%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s%s\n\n", colorCyan, skill.Why(), colorReset)

	if inPlace {
		fmt.Printf("%s%sThis configuration is already in place. These commands are not run now;%s\n", colorBold, colorBlue, colorReset)
		fmt.Printf("%s%sapproving them lets fogbot restore it if it goes missing:%s\n\n", colorBold, colorBlue, colorReset)
	} else {
		fmt.Printf("%s%sThe following commands will be executed:%s\n\n", colorBold, colorBlue, colorReset)
	}
	printCommands(commands)

	fmt.Printf("%s%sNOTE:%s Fogbot will check system configuration on each startup.\n", colorBold, colorYellow, colorReset)
	fmt.Printf("      If these configurations are missing, approved commands will\n")
	fmt.Printf("      be automatically re-applied while this skill is enabled.\n\n")

	if err := confirm("Do you approve these commands?"); err != nil {
		return err
	}

	// Record approval
	for _, cmd := range commands {
		if err := e.approvalTracker.Approve(skill.ID(), skill.Name(), cmd); err != nil {
			return fmt.Errorf("failed to record approval: %w", err)
		}
	}

	fmt.Printf("\n✓ Approval recorded\n")
	return nil
}

func printCommands(commands []SystemCommand) {
	for i, cmd := range commands {
		fmt.Printf("  %s%d. %s%s\n", colorBold, i+1, cmd.Description, colorReset)
		fmt.Printf("     %s%s%s\n\n", colorRed, cmd.Command, colorReset)
	}
}

// confirm asks a yes/no question on stdin, returning an error unless the
// answer is yes
func confirm(question string) error {
	fmt.Printf("%s%s [y/N]: %s", colorBold, question, colorReset)

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	response = strings.ToLower(strings.TrimSpace(response))
	if response != "y" && response != "yes" {
		return fmt.Errorf("user denied approval")
	}
	return nil
}

// Disable removes the system configuration skill put in place, once the user
// approves the commands that do it, then revokes the skill's approvals. Before,
// disabling only revoked approvals: the rules stayed, so a later enable found
// them in place, recorded no approval, and startup repair could never restore
// them. The removal commands are not recorded, as nothing repeats them.
func (e *Enabler) Disable(skill Skill) error {
	if t, ok := skill.(Teardowner); ok {
		commands, err := t.TeardownCommands()
		switch {
		case err != nil && e.dryRun:
			// Dry-run usually runs unprivileged, where the rules can't be read
			fmt.Printf("  [dry-run] Could not list system configuration to remove (%v)\n", err)
		case err != nil:
			return fmt.Errorf("failed to work out what to remove: %w", err)
		case len(commands) > 0:
			fmt.Printf("\n%s%sDisabling '%s' removes its system configuration:%s\n\n", colorBold, colorYellow, skill.Name(), colorReset)
			printCommands(commands)
			if err := confirm("Run these commands?"); err != nil {
				return err
			}
			fmt.Printf("\nRemoving configuration for skill '%s'...\n", skill.Name())
			for _, cmd := range commands {
				if err := e.executeCommand(cmd); err != nil {
					return fmt.Errorf("failed to execute command: %w", err)
				}
			}
		}
	}

	if err := e.approvalTracker.RevokeSkill(skill.ID()); err != nil {
		return fmt.Errorf("failed to revoke approvals: %w", err)
	}
	return nil
}

// SetDryRun makes the enabler print commands instead of running them
func (e *Enabler) SetDryRun(enabled bool) {
	e.dryRun = enabled
}

// executeCommand runs a system command
func (e *Enabler) executeCommand(cmd SystemCommand) error {
	if e.dryRun {
		fmt.Printf("  [dry-run] Would execute: %s\n", cmd.Command)
		return nil
	}
	fmt.Printf("  Executing: %s\n", cmd.Description)

	parts, err := shellquote.Split(cmd.Command)
	if err != nil {
		return fmt.Errorf("failed to parse command %q: %w", cmd.Command, err)
	}
	if len(parts) == 0 {
		return fmt.Errorf("empty command")
	}

	execCmd := exec.Command(parts[0], parts[1:]...)
	output, err := execCmd.CombinedOutput()
	if err != nil {
		// auditctl exits non-zero when the rule already exists; treat this as success
		if strings.Contains(string(output), "Rule exists") {
			fmt.Printf("  (rule already exists, skipping)\n")
			return nil
		}
		return fmt.Errorf("command failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}

// ReapplyOnStartup checks and reapplies approved commands if system state is missing
func (e *Enabler) ReapplyOnStartup(skill Skill) error {
	if !skill.Enabled() {
		return nil // Skip disabled skills
	}

	// Check if system is properly configured
	isConfigured, err := skill.CheckSystemState()
	if err != nil {
		return fmt.Errorf("failed to check system state: %w", err)
	}

	if isConfigured {
		return nil // Already configured, nothing to do
	}

	// Re-derive the commands from the skill's config so they run in the order the
	// skill generates them (the tracker stores them unordered), and only run the
	// ones the user approved. A command whose config changed since approval is
	// skipped rather than run unapproved.
	commands, err := skill.DeduceCommands(skill.Config())
	if err != nil {
		return fmt.Errorf("failed to deduce commands: %w", err)
	}

	var approved []SystemCommand
	for _, cmd := range commands {
		if e.approvalTracker.IsApproved(skill.ID(), cmd.Command) {
			approved = append(approved, cmd)
		} else {
			log.Printf("[startup-repair] Skipping unapproved command for '%s': %s", skill.Name(), cmd.Command)
		}
	}
	if len(approved) == 0 {
		return fmt.Errorf("configuration missing and no approved commands to restore it; re-enable the skill with 'fogbot skill enable %d'", skill.ID())
	}

	log.Printf("[startup-repair] Skill '%s' configuration missing from system, reapplying %d approved commands", skill.Name(), len(approved))
	for _, cmd := range approved {
		if err := e.executeCommand(cmd); err != nil {
			return fmt.Errorf("failed to reapply command: %w", err)
		}
	}

	if len(approved) < len(commands) {
		return fmt.Errorf("reapplied %d of %d commands; re-enable the skill to approve the rest", len(approved), len(commands))
	}

	log.Printf("[startup-repair] Configuration reapplied for skill '%s'", skill.Name())
	return nil
}
