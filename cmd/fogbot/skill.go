package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"text/tabwriter"

	"github.com/AlecAivazis/survey/v2"
	"github.com/penguinpowernz/fogbot/internal/approval"
	"github.com/penguinpowernz/fogbot/internal/skills"
	"github.com/penguinpowernz/fogbot/internal/skills/dirwatch"
	"github.com/penguinpowernz/fogbot/internal/skills/porttripwires"
	"github.com/penguinpowernz/fogbot/internal/skills/systemdwatch"
	"github.com/spf13/cobra"
)

var (
	approvalTracker *approval.Tracker
	skillEnabler    *skills.Enabler
)

// approvalTrackerAdapter adapts approval.Tracker to skills.ApprovalTracker
type approvalTrackerAdapter struct {
	tracker *approval.Tracker
}

func (a *approvalTrackerAdapter) Approve(skillID int, skillName string, cmd skills.CommandInfo) error {
	return a.tracker.Approve(skillID, skillName, cmd)
}

func (a *approvalTrackerAdapter) IsApproved(skillID int, command string) bool {
	return a.tracker.IsApproved(skillID, command)
}

func (a *approvalTrackerAdapter) GetApprovedCommands(skillID int) []skills.ApprovedCommand {
	approved := a.tracker.GetApprovedCommands(skillID)
	result := make([]skills.ApprovedCommand, len(approved))
	for i, cmd := range approved {
		result[i] = skills.ApprovedCommand{
			SkillID:     cmd.SkillID,
			SkillName:   cmd.SkillName,
			Command:     cmd.Command,
			Description: cmd.Description,
			Metadata:    cmd.Metadata,
		}
	}
	return result
}

func (a *approvalTrackerAdapter) RevokeSkill(skillID int) error {
	return a.tracker.RevokeSkill(skillID)
}

func initSkillSystem(stateDir string) error {
	var err error
	// Use stateDir from global flags if provided, otherwise use build-time default
	trackerPath := "/var/lib/fogbot"
	if stateDir != "" {
		trackerPath = stateDir
	}
	approvalTracker, err = approval.NewTracker(trackerPath)
	if err != nil {
		return fmt.Errorf("failed to initialize approval tracker: %w", err)
	}
	adapter := &approvalTrackerAdapter{tracker: approvalTracker}
	skillEnabler = skills.NewEnabler(adapter)
	return nil
}

func newSkillCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "skill",
		Aliases: []string{"s", "skills"},
		Short:   "Manage fogbot skills",
		Run:     runSkillInteractive, // Run interactive picker when no subcommand
	}

	listCmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"l", "ls"},
		Short:   "List all available skills",
		Run:     runSkillList,
	}
	cmd.AddCommand(listCmd)

	enableCmd := &cobra.Command{
		Use:     "enable <skill-name-or-id>",
		Aliases: []string{"e"},
		Short:   "Enable a skill by name or ID",
		Args:    cobra.ExactArgs(1),
		Run:     runSkillEnable,
	}
	cmd.AddCommand(enableCmd)

	disableCmd := &cobra.Command{
		Use:     "disable <skill-name-or-id>",
		Aliases: []string{"d"},
		Short:   "Disable a skill by name or ID",
		Args:    cobra.ExactArgs(1),
		Run:     runSkillDisable,
	}
	cmd.AddCommand(disableCmd)

	infoCmd := &cobra.Command{
		Use:   "info <skill-name-or-id>",
		Short: "Show detailed information about a skill",
		Args:  cobra.ExactArgs(1),
		Run:   runSkillInfo,
	}
	cmd.AddCommand(infoCmd)

	return cmd
}

func runSkillList(cmd *cobra.Command, args []string) {
	// Load available skills
	available, err := skills.LoadAvailable("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading skills: %v\n", err)
		os.Exit(1)
	}

	// Load enabled skills
	enabled, err := skills.LoadEnabled("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading enabled skills: %v\n", err)
		os.Exit(1)
	}

	// Sort by ID
	sort.Slice(available, func(i, j int) bool {
		return available[i].ID < available[j].ID
	})

	// Print table
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, " ID\tSKILL\tSTATUS\tREQUIRES\tDESCRIPTION")
	fmt.Fprintln(w, " ───\t─────────────────\t────────\t────────────────────\t──────────────────────────────────────")

	for _, skill := range available {
		status := "disabled"
		if enabled[skill.ID] {
			status = "enabled"
		}

		// Truncate description
		desc := skill.Description
		if len(desc) > 50 {
			desc = desc[:47] + "..."
		}

		// Join requires
		req := ""
		if len(skill.Requires) > 0 {
			req = skill.Requires[0]
			if len(skill.Requires) > 1 {
				req += fmt.Sprintf(" +%d", len(skill.Requires)-1)
			}
		}

		fmt.Fprintf(w, " %3d\t%s\t%s\t%s\t%s\n",
			skill.ID, skill.Name, status, req, desc)
	}

	w.Flush()
}

func runSkillEnable(cmd *cobra.Command, args []string) {
	skillNameOrID := args[0]

	// Initialize skill system with stateDir from global flag if set
	if err := initSkillSystem(stateDir); err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing skill system: %v\n", err)
		os.Exit(1)
	}

	// Resolve skill name from ID if needed
	skillName, err := resolveSkillName(skillNameOrID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Check if already enabled
	if skills.IsEnabled(skillName, "") {
		fmt.Printf("Skill %s is already enabled\n", skillName)
		return
	}

	// Load skill config
	available, err := skills.LoadAvailable("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading skills: %v\n", err)
		os.Exit(1)
	}

	var skillConfig *skills.SkillConfig
	for i := range available {
		if available[i].Name == skillName {
			skillConfig = &available[i]
			break
		}
	}

	if skillConfig == nil {
		fmt.Fprintf(os.Stderr, "Skill %s not found\n", skillName)
		os.Exit(1)
	}

	// Instantiate the skill implementation
	skill := instantiateSkill(*skillConfig)
	if skill == nil {
		fmt.Fprintf(os.Stderr, "Skill %s does not have an implementation yet\n", skillName)
		os.Exit(1)
	}

	// Use the Enabler to handle the full workflow
	if err := skillEnabler.Enable(skill, skillConfig.RequiresApproval); err != nil {
		fmt.Fprintf(os.Stderr, "Error enabling skill: %v\n", err)
		os.Exit(1)
	}

	// Create the symlink after successful enablement
	if err := skills.Enable(skillName, "", ""); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating symlink: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nReload fogbot daemon to activate: systemctl reload fogbot (or kill -HUP)\n")
}

// instantiateSkill creates a skill implementation from config
func instantiateSkill(cfg skills.SkillConfig) skills.Skill {
	// Match skill by ID to instantiate the right implementation
	switch cfg.ID {
	case 510:
		return porttripwires.New(cfg)
	case 540:
		return dirwatch.NewFromConfig(cfg)
	case 550:
		return systemdwatch.NewFromConfig(cfg)
	// Add more skill implementations here as they're created
	default:
		return nil
	}
}

func runSkillDisable(cmd *cobra.Command, args []string) {
	skillNameOrID := args[0]

	// Initialize skill system to revoke approvals
	if err := initSkillSystem(stateDir); err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing skill system: %v\n", err)
		os.Exit(1)
	}

	// Resolve skill name from ID if needed
	skillName, err := resolveSkillName(skillNameOrID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Check if enabled
	if !skills.IsEnabled(skillName, "") {
		fmt.Printf("Skill %s is not enabled\n", skillName)
		return
	}

	// Get skill ID to revoke approvals
	available, err := skills.LoadAvailable("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading skills: %v\n", err)
		os.Exit(1)
	}

	var skillID int
	for _, skill := range available {
		if skill.Name == skillName {
			skillID = skill.ID
			break
		}
	}

	// Revoke all approvals for this skill
	if skillID > 0 {
		if err := approvalTracker.RevokeSkill(skillID); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to revoke approvals: %v\n", err)
		}
	}

	// Disable the skill
	if err := skills.Disable(skillName, ""); err != nil {
		fmt.Fprintf(os.Stderr, "Error disabling skill: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Skill %s disabled successfully\n", skillName)
	fmt.Printf("Approvals revoked for this skill\n")
	fmt.Printf("Reload fogbot daemon to deactivate: systemctl reload fogbot (or kill -HUP)\n")
}

func runSkillInfo(cmd *cobra.Command, args []string) {
	skillNameOrID := args[0]

	// Resolve skill name from ID if needed
	skillName, err := resolveSkillName(skillNameOrID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Load skill config
	available, err := skills.LoadAvailable("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading skills: %v\n", err)
		os.Exit(1)
	}

	// Find the skill
	var skill *skills.SkillConfig
	for i := range available {
		if available[i].Name == skillName {
			skill = &available[i]
			break
		}
	}

	if skill == nil {
		fmt.Fprintf(os.Stderr, "Skill %s not found\n", skillName)
		os.Exit(1)
	}

	// Check if enabled
	enabled := skills.IsEnabled(skillName, "")
	status := "disabled"
	if enabled {
		status = "enabled"
	}

	// Print detailed info
	fmt.Printf("Skill: %s (ID: %d)\n", skill.Name, skill.ID)
	fmt.Printf("Status: %s\n", status)
	fmt.Printf("\n")
	fmt.Printf("Description:\n%s\n", skill.Description)
	fmt.Printf("\n")
	fmt.Printf("Why:\n%s\n", skill.Why)
	fmt.Printf("\n")
	fmt.Printf("Requirements: %v\n", skill.Requires)
	fmt.Printf("Tags: %v\n", skill.Tags)
	fmt.Printf("Default Severity: %s\n", skill.SeverityDefault)
	fmt.Printf("\n")
	fmt.Printf("Config:\n")
	for k, v := range skill.Config {
		fmt.Printf("  %s: %v\n", k, v)
	}
}

// resolveSkillName resolves a skill name or ID to a skill name
func resolveSkillName(nameOrID string) (string, error) {
	// Try to parse as ID first
	if id, err := strconv.Atoi(nameOrID); err == nil {
		// It's an ID, find the corresponding skill name
		available, err := skills.LoadAvailable("")
		if err != nil {
			return "", fmt.Errorf("loading skills: %w", err)
		}

		for _, skill := range available {
			if skill.ID == id {
				return skill.Name, nil
			}
		}
		return "", fmt.Errorf("skill with ID %d not found", id)
	}

	// It's already a name
	return nameOrID, nil
}

// runSkillInteractive shows an interactive picker for enabling/disabling skills
func runSkillInteractive(cmd *cobra.Command, args []string) {
	// Load available skills
	available, err := skills.LoadAvailable("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading skills: %v\n", err)
		os.Exit(1)
	}

	// Load enabled skills
	enabled, err := skills.LoadEnabled("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading enabled skills: %v\n", err)
		os.Exit(1)
	}

	// Sort by ID
	sort.Slice(available, func(i, j int) bool {
		return available[i].ID < available[j].ID
	})

	// Create options with nice formatting
	type option struct {
		display string
		skill   skills.SkillConfig
		enabled bool
	}

	options := make([]option, len(available))
	optionStrings := make([]string, len(available))
	defaults := make([]int, 0)

	for i, skill := range available {
		isEnabled := enabled[skill.ID]
		if isEnabled {
			defaults = append(defaults, i)
		}

		// Truncate description for display
		desc := skill.Description
		if len(desc) > 60 {
			desc = desc[:57] + "..."
		}

		// Format: 100 ssh-monitor - SSH brute force, new-IP logins, root login
		// Survey will add its own checkboxes
		display := fmt.Sprintf("%3d %-20s - %s", skill.ID, skill.Name, desc)

		options[i] = option{
			display: display,
			skill:   skill,
			enabled: isEnabled,
		}
		optionStrings[i] = display
	}

	// Show multiselect prompt
	var selectedIndices []int
	prompt := &survey.MultiSelect{
		Message: "Select skills to enable (space to toggle, enter to confirm):",
		Options: optionStrings,
		Default: defaults,
		Help:    "Use arrow keys to navigate, space to toggle, enter to save",
	}

	err = survey.AskOne(prompt, &selectedIndices, survey.WithPageSize(15))
	if err != nil {
		// User cancelled
		fmt.Println("\nCancelled")
		return
	}

	// Determine what changed
	selectedMap := make(map[int]bool)
	for _, idx := range selectedIndices {
		selectedMap[idx] = true
	}

	toEnable := make([]skills.SkillConfig, 0)
	toDisable := make([]skills.SkillConfig, 0)

	for i, opt := range options {
		wasEnabled := opt.enabled
		nowEnabled := selectedMap[i]

		if !wasEnabled && nowEnabled {
			toEnable = append(toEnable, opt.skill)
		} else if wasEnabled && !nowEnabled {
			toDisable = append(toDisable, opt.skill)
		}
	}

	// Apply changes
	if len(toEnable) == 0 && len(toDisable) == 0 {
		fmt.Println("No changes made")
		return
	}

	fmt.Println("\nApplying changes...")

	// Initialize skill system with stateDir from global flag if set
	if err := initSkillSystem(stateDir); err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing skill system: %v\n", err)
		os.Exit(1)
	}

	// Enable skills
	for _, skillCfg := range toEnable {
		// Instantiate the skill implementation
		skill := instantiateSkill(skillCfg)
		if skill == nil {
			// Skill doesn't have implementation yet, use old method
			if err := skills.Enable(skillCfg.Name, "", ""); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ Failed to enable %s: %v\n", skillCfg.Name, err)
			} else {
				fmt.Printf("  ✓ Enabled %s (#%d)\n", skillCfg.Name, skillCfg.ID)
			}
			continue
		}

		// Use the Enabler for skills with implementations
		if err := skillEnabler.Enable(skill, skillCfg.RequiresApproval); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ Failed to enable %s: %v\n", skillCfg.Name, err)
			continue
		}

		// Create the symlink after successful enablement
		if err := skills.Enable(skillCfg.Name, "", ""); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ Failed to create symlink for %s: %v\n", skillCfg.Name, err)
		} else {
			fmt.Printf("  ✓ Enabled %s (#%d)\n", skillCfg.Name, skillCfg.ID)
		}
	}

	// Disable skills
	for _, skill := range toDisable {
		// Revoke approvals when disabling
		if err := approvalTracker.RevokeSkill(skill.ID); err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠ Warning: failed to revoke approvals for %s: %v\n", skill.Name, err)
		}

		if err := skills.Disable(skill.Name, ""); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ Failed to disable %s: %v\n", skill.Name, err)
		} else {
			fmt.Printf("  ✓ Disabled %s (#%d)\n", skill.Name, skill.ID)
		}
	}

	fmt.Printf("\nReload fogbot daemon to apply changes: systemctl reload fogbot (or kill -HUP)\n")
}
