package skills

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Enabler handles the process of enabling skills with user approval
type Enabler struct {
	approvalTracker ApprovalTracker
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

// NewEnabler creates a new skill enabler
func NewEnabler(tracker ApprovalTracker) *Enabler {
	return &Enabler{
		approvalTracker: tracker,
	}
}

// Enable handles the full enablement workflow for a skill
func (e *Enabler) Enable(skill Skill, requiresApproval bool) error {
	// Step 1: Check if system is already configured
	isConfigured, err := skill.CheckSystemState()
	if err != nil {
		return fmt.Errorf("failed to check system state: %w", err)
	}

	if isConfigured {
		fmt.Printf("✓ Skill '%s' configuration already exists in system\n", skill.Name())
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

	// Step 3: Filter out already-approved commands
	needsApproval := []SystemCommand{}
	for _, cmd := range commands {
		if requiresApproval && !e.approvalTracker.IsApproved(skill.ID(), cmd.Command) {
			needsApproval = append(needsApproval, cmd)
		}
	}

	// Step 4: Request approval if needed
	if requiresApproval && len(needsApproval) > 0 {
		if err := e.requestApproval(skill, needsApproval); err != nil {
			return fmt.Errorf("approval denied or failed: %w", err)
		}
	}

	// Step 5: Execute all commands
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

// requestApproval presents commands to user and requests approval
func (e *Enabler) requestApproval(skill Skill, commands []SystemCommand) error {
	fmt.Printf("\n%s%s┌─────────────────────────────────────────────────────────────────┐%s\n", colorBold, colorYellow, colorReset)
	fmt.Printf("%s%s│ ⚠  Skill '%s' requires system configuration%s\n", colorBold, colorYellow, skill.Name(), colorReset)
	fmt.Printf("%s%s└─────────────────────────────────────────────────────────────────┘%s\n\n", colorBold, colorYellow, colorReset)

	fmt.Printf("%s%sWhy this skill matters:%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s%s\n\n", colorCyan, skill.Why(), colorReset)

	fmt.Printf("%s%sThe following commands will be executed:%s\n\n", colorBold, colorBlue, colorReset)
	for i, cmd := range commands {
		fmt.Printf("  %s%d. %s%s\n", colorBold, i+1, cmd.Description, colorReset)
		fmt.Printf("     %s%s%s\n\n", colorRed, cmd.Command, colorReset)
	}

	fmt.Printf("%s%sNOTE:%s Fogbot will check system configuration on each startup.\n", colorBold, colorYellow, colorReset)
	fmt.Printf("      If these configurations are missing, approved commands will\n")
	fmt.Printf("      be automatically re-applied while this skill is enabled.\n\n")

	fmt.Printf("%sDo you approve these commands? [y/N]: %s", colorBold, colorReset)

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	response = strings.ToLower(strings.TrimSpace(response))
	if response != "y" && response != "yes" {
		return fmt.Errorf("user denied approval")
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

// executeCommand runs a system command
func (e *Enabler) executeCommand(cmd SystemCommand) error {
	fmt.Printf("  Executing: %s\n", cmd.Description)

	parts := strings.Fields(cmd.Command)
	if len(parts) == 0 {
		return fmt.Errorf("empty command")
	}

	execCmd := exec.Command(parts[0], parts[1:]...)
	output, err := execCmd.CombinedOutput()
	if err != nil {
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

	// Get approved commands for this skill
	approvedCmds := e.approvalTracker.GetApprovedCommands(skill.ID())
	if len(approvedCmds) == 0 {
		return fmt.Errorf("skill enabled but no approved commands found")
	}

	fmt.Printf("⚠ Skill '%s' configuration missing from system, reapplying...\n", skill.Name())

	// Re-execute approved commands
	for _, approved := range approvedCmds {
		cmd := SystemCommand{
			Command:     approved.Command,
			Description: approved.Description,
			Metadata:    approved.Metadata,
		}
		if err := e.executeCommand(cmd); err != nil {
			return fmt.Errorf("failed to reapply command: %w", err)
		}
	}

	fmt.Printf("✓ Configuration reapplied for skill '%s'\n", skill.Name())
	return nil
}
