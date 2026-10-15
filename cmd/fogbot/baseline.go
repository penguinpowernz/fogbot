package main

import (
	"fmt"
	"os"
	"os/user"
	"sort"
	"strconv"
	"unicode"

	"github.com/AlecAivazis/survey/v2"
	"github.com/penguinpowernz/fogbot/internal/baseline"
	"github.com/spf13/cobra"
)

// Baselines are approved on the host as root rather than over Telegram, so that
// whoever holds the authorized chat can't whitelist a planted SUID binary.
func newBaselineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "baseline",
		Aliases: []string{"b"},
		Short:   "Review and approve detection baselines",
		// Errors here are operational (not root, unreadable state), not usage mistakes
		SilenceUsage: true,
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "diff",
		Short: "Show how the pending SUID/SGID baseline differs from the approved one",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, _, err := loadBaselineChanges()
			return err
		},
	})

	var yes bool
	approveCmd := &cobra.Command{
		Use:   "approve",
		Short: "Approve the pending SUID/SGID baseline (requires root)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBaselineApprove(yes)
		},
	}
	approveCmd.Flags().BoolVarP(&yes, "yes", "y", false, "Approve without prompting")
	cmd.AddCommand(approveCmd)

	return cmd
}

func baselineManager() *baseline.Manager {
	return baseline.NewManager(resolveStateDir())
}

// loadBaselineChanges prints the pending baseline's changes against the
// approved one and returns the manager and pending baseline.
func loadBaselineChanges() (*baseline.Manager, *baseline.Baseline, error) {
	mgr := baselineManager()

	pending, err := mgr.LoadPendingSuid()
	if err != nil {
		return nil, nil, err
	}
	if pending == nil {
		fmt.Println("No pending SUID/SGID baseline.")
		return mgr, nil, nil
	}

	active, err := mgr.LoadSuid()
	if err != nil {
		return nil, nil, err
	}

	if active == nil || !active.Approved {
		fmt.Printf("Initial SUID/SGID baseline: %d binaries\n\n", len(pending.Entries))
		printEntries("  ", entriesOf(pending.Entries))
		return mgr, pending, nil
	}

	added := active.Diff(pending.Entries)
	changed := active.Changed(pending.Entries)
	removed := pending.Diff(active.Entries)

	if len(added)+len(changed)+len(removed) == 0 {
		fmt.Println("Pending SUID/SGID baseline matches the approved one.")
		return mgr, pending, nil
	}

	fmt.Printf("SUID/SGID baseline changes (created %s):\n\n", pending.CreatedAt.Format("2006-01-02 15:04:05"))
	printEntries("+ ", added)
	printEntries("~ ", changed)
	printEntries("- ", removed)
	return mgr, pending, nil
}

func runBaselineApprove(yes bool) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("baseline approval must be run as root")
	}

	mgr, pending, err := loadBaselineChanges()
	if err != nil || pending == nil {
		return err
	}

	if !yes {
		approve := false
		if err := survey.AskOne(&survey.Confirm{Message: "Approve this baseline?"}, &approve); err != nil {
			return err
		}
		if !approve {
			fmt.Println("Not approved.")
			return nil
		}
	}

	if err := mgr.ApproveReviewedSuid(pending, approver()); err != nil {
		return err
	}
	fmt.Printf("SUID/SGID baseline approved (%d binaries).\n", len(pending.Entries))
	return nil
}

// approver records who approved the baseline, preferring the user behind sudo
func approver() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return "cli:" + u
	}
	if u, err := user.Current(); err == nil {
		return "cli:" + u.Username
	}
	return "cli"
}

func entriesOf(m map[string]baseline.SuidEntry) []baseline.SuidEntry {
	entries := make([]baseline.SuidEntry, 0, len(m))
	for _, e := range m {
		entries = append(entries, e)
	}
	return entries
}

func printEntries(prefix string, entries []baseline.SuidEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	for _, e := range entries {
		fmt.Printf("%s%-40s %s uid=%d gid=%d sha256=%.12s\n", prefix, displayPath(e.Path), os.FileMode(e.Mode), e.UID, e.GID, e.Hash)
	}
}

// displayPath quotes a path that contains anything unprintable. File names are
// chosen by whoever planted the binary, and raw escape sequences in one could
// erase or rewrite its line in the operator's terminal before they approve.
func displayPath(path string) string {
	for _, r := range path {
		if !unicode.IsPrint(r) {
			return strconv.Quote(path)
		}
	}
	return path
}
