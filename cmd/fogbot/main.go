package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"


	"github.com/penguinpowernz/fogbot/internal/auth"
	"github.com/penguinpowernz/fogbot/internal/baseline"
	"github.com/penguinpowernz/fogbot/internal/config"
	"github.com/penguinpowernz/fogbot/internal/dedup"
	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/notifier/telegram"
	"github.com/penguinpowernz/fogbot/internal/selfwatch"
	"github.com/penguinpowernz/fogbot/internal/skills"
	"github.com/penguinpowernz/fogbot/internal/skills/auditdhealth"
	"github.com/penguinpowernz/fogbot/internal/skills/cronwatch"
	"github.com/penguinpowernz/fogbot/internal/skills/dirwatch"
	"github.com/penguinpowernz/fogbot/internal/skills/filewatch"
	"github.com/penguinpowernz/fogbot/internal/skills/logfreshness"
	"github.com/penguinpowernz/fogbot/internal/skills/systemdwatch"
	"github.com/penguinpowernz/fogbot/internal/skills/pkgmonitor"
	"github.com/penguinpowernz/fogbot/internal/skills/netdiscover"
	"github.com/penguinpowernz/fogbot/internal/skills/porttripwires"
	"github.com/penguinpowernz/fogbot/internal/skills/procexec"
	"github.com/penguinpowernz/fogbot/internal/skills/servicehealth"
	"github.com/penguinpowernz/fogbot/internal/skills/sshmonitor"
	"github.com/penguinpowernz/fogbot/internal/skills/suidsweep"
	"github.com/spf13/cobra"
)

var (
	Version   = "dev"
	BuildTime = "unknown"

	configPath      string
	stateDir        string
	skillsAvailable string
	skillsEnabled   string
	hostLabel       string
	dryRun          bool

	daemonStartTime time.Time // Track when daemon started for uptime reporting
)

// initFlagsFromEnv initializes flag defaults from environment variables.
// Called before Cobra parses flags so env vars can set sensible defaults.
func initFlagsFromEnv() {
	if v := os.Getenv("FOGBOT_CONFIG"); v != "" {
		configPath = v
	}
	if v := os.Getenv("FOGBOT_STATE_DIR"); v != "" {
		stateDir = v
	}
	if v := os.Getenv("FOGBOT_SKILLS_AVAILABLE"); v != "" {
		skillsAvailable = v
	}
	if v := os.Getenv("FOGBOT_SKILLS_ENABLED"); v != "" {
		skillsEnabled = v
	}
	if v := os.Getenv("FOGBOT_HOST_LABEL"); v != "" {
		hostLabel = v
	}
	if v := os.Getenv("FOGBOT_DRY_RUN"); v == "true" || v == "1" {
		dryRun = true
	}
}

// resolveStateDir picks the state directory: --state-dir or $FOGBOT_STATE_DIR,
// then state_dir from the config file, then the built-in default.
func resolveStateDir() string {
	if stateDir != "" {
		return stateDir
	}
	if cfg, err := config.Load(resolveConfigPath()); err == nil {
		return cfg.StateDir
	}
	return config.DefaultStateDir
}

func resolveConfigPath() string {
	if configPath != "" {
		return configPath
	}
	return config.DefaultConfigPath
}

func main() {
	// Initialize flag values from environment variables or defaults
	initFlagsFromEnv()

	rootCmd := &cobra.Command{
		Use:   "fogbot",
		Short: "Linux intrusion detection via Telegram",
		Long:  "A Go daemon that monitors detection subsystems and reports anomalies via Telegram",
		// Runs for every subcommand, so skill commands honour the path flags too
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// OverrideSkillsPaths ignores empty strings, preserving package-level env defaults
			skills.OverrideSkillsPaths(skillsAvailable, skillsEnabled)
		},
	}

	// Add global flags - available to ALL commands, not just daemon.
	// Defaults are the env values read above, so a flag overrides its env var.
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", configPath, "Path to config file (default: $FOGBOT_CONFIG)")
	rootCmd.PersistentFlags().StringVarP(&stateDir, "state-dir", "s", stateDir, "State directory (default: $FOGBOT_STATE_DIR, else state_dir in config)")
	rootCmd.PersistentFlags().StringVar(&skillsAvailable, "skills-available", skillsAvailable, "Skills available directory (default: $FOGBOT_SKILLS_AVAILABLE)")
	rootCmd.PersistentFlags().StringVar(&skillsEnabled, "skills-enabled", skillsEnabled, "Skills enabled directory (default: $FOGBOT_SKILLS_ENABLED)")
	rootCmd.PersistentFlags().StringVar(&hostLabel, "host-label", hostLabel, "Host label for alerts (default: $FOGBOT_HOST_LABEL or hostname)")
	rootCmd.PersistentFlags().BoolVarP(&dryRun, "dry-run", "d", dryRun, "Dry-run mode - no system modifications ($FOGBOT_DRY_RUN)")

	// Version command - standalone, doesn't need global flags
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("fogbot %s (built %s)\n", Version, BuildTime)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "daemon",
		Short: "Start the fogbot daemon",
		Run:   runDaemon,
	})

	// Add CLI subcommands (to be implemented) - now have access to global flags
	rootCmd.AddCommand(newSkillCmd())
	rootCmd.AddCommand(newBaselineCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runDaemon(cmd *cobra.Command, args []string) {
	daemonStartTime = time.Now() // Record start time for uptime tracking
	log.Printf("fogbot %s starting...", Version)

	configPathToUse := resolveConfigPath()

	// Alerts name the real hostname (never host_label from the config file),
	// unless overridden with --host-label or $FOGBOT_HOST_LABEL
	machineHostname := hostLabel
	if machineHostname == "" {
		machineHostname, _ = os.Hostname()
	}
	if dryRun {
		log.Printf("Dry-run mode: system commands will be printed, not run")
	}

	// Load config
	cfg, err := config.Load(configPathToUse)
	if err != nil {
		// Load wraps the error, so os.IsNotExist can't see through it
		if errors.Is(err, fs.ErrNotExist) {
			log.Printf("Config file %s not found, using defaults", configPathToUse)
			cfg = config.Default()
		} else {
			log.Fatalf("Failed to load config: %v", err)
		}
	}

	// --state-dir / $FOGBOT_STATE_DIR override state_dir from the config file
	if stateDir != "" {
		cfg.StateDir = stateDir
	}

	// Create state directory
	if err := os.MkdirAll(cfg.StateDir, 0700); err != nil {
		log.Fatalf("Failed to create state directory: %v", err)
	}

	// Initialize auth state
	statePath := filepath.Join(cfg.StateDir, "state.json")
	authState, err := auth.NewState(statePath)
	if err != nil {
		log.Fatalf("Failed to initialize auth state: %v", err)
	}

	// Check authorization status
	if authState.IsAnyoneAuthorized() {
		log.Printf("Already authorized (chat_id in state.json)")
	} else {
		log.Printf("Not yet authorized - waiting for /start command from Telegram")
	}

	// Initialize Telegram notifier
	var notif notifier.Notifier
	if cfg.GetTelegramToken() != "" {
		notif = telegram.NewTelegram(
			cfg.GetTelegramToken(),
			cfg.GetTelegramChatID(),
			authState,
		)
		log.Printf("Telegram notifier initialized")
	} else {
		log.Printf("No Telegram token configured, alerts will be logged only")
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize dedup engine
	dedupEngine := dedup.NewEngine(cfg.Dedup.Window, cfg.Dedup.MaxBurst, cfg.Dedup.ContactBurst)
	defer dedupEngine.Close()

	// Initialize baseline manager
	baselineManager := baseline.NewManager(cfg.StateDir)

	// Initialize skill registry and register all skills
	registry := skills.NewRegistry()
	registry.Register(sshmonitor.New())
	registry.Register(suidsweep.New(baselineManager))
	registry.Register(procexec.New())
	registry.Register(pkgmonitor.New())
	registry.Register(logfreshness.New())
	registry.Register(servicehealth.New())
	registry.Register(auditdhealth.New())
	registry.Register(filewatch.NewDefault())
	registry.Register(porttripwires.NewDefault())
	registry.Register(cronwatch.New())
	registry.Register(dirwatch.New())
	registry.Register(systemdwatch.New())
	registry.Register(netdiscover.New(baselineManager))

	// Log registered skills
	log.Printf("Skill registry initialized with %d skills:", len(registry.All()))
	for _, skill := range registry.All() {
		log.Printf("  - #%d: %s", skill.ID(), skill.Name())
	}

	// Load enabled skills from filesystem
	log.Printf("Loading enabled skills from: %s", skills.SkillsEnabledPath)
	enabledSkillConfigs, err := skills.LoadEnabledConfigs(skills.SkillsEnabledPath)
	if err != nil {
		log.Fatalf("Failed to load enabled skills: %v", err)
	}
	log.Printf("Found %d enabled skill configs", len(enabledSkillConfigs))

	// All watchers feed one bus, so skills can be started and stopped on reload
	alertBus := make(chan notifier.Alert, 100)
	go processAlerts(ctx, alertBus, dedupEngine, notif, machineHostname)

	skillMgr := newSkillManager(ctx, registry, alertBus, machineHostname)

	// Startup repair: restore system config (auditctl rules, iptables rules) that
	// didn't survive a reboot, using only previously approved commands
	if err := initSkillSystem(cfg.StateDir); err != nil {
		log.Printf("Startup repair unavailable: %v", err)
	} else {
		skillMgr.repair = func(skill skills.Skill) error {
			// Only what is approved now may run: `fogbot skill disable`
			// removes a skill's config and revokes its approvals, which must
			// not be put back before the daemon is reloaded
			if err := approvalTracker.Reload(); err != nil {
				return fmt.Errorf("reloading approved commands: %w", err)
			}
			return skillEnabler.ReapplyOnStartup(skill)
		}
		// A skill disabled on the host but still running until the next
		// reload has had its config removed on purpose
		skillMgr.enabledOnDisk = func(skill skills.Skill) bool {
			return skills.IsEnabled(skill.Name(), "")
		}
	}

	log.Printf("Skills: %s", skillMgr.apply(enabledSkillConfigs))
	go skillMgr.watchSystemState(stateCheckInterval)

	// Start selfwatch to monitor fogbot's own files
	binaryPath, _ := os.Executable()
	sw, err := selfwatch.New(binaryPath, configPathToUse, cfg.StateDir)
	if err != nil {
		log.Printf("Failed to create selfwatch: %v", err)
	} else {
		sw.WatchSkillDirs(skills.SkillsAvailablePath, skills.SkillsEnabledPath)
		selfwatchChan, err := sw.Watch(ctx, machineHostname)
		if err != nil {
			log.Printf("Failed to start selfwatch: %v", err)
		} else {
			go func() {
				forwardAlerts(ctx, selfwatchChan, alertBus)
				if ctx.Err() == nil {
					log.Printf("Selfwatch stopped unexpectedly")
					skillMgr.send(notifier.Alert{
						Severity:    notifier.SeverityContact,
						SkillID:     999,
						SkillName:   "selfwatch",
						Title:       "[DEADMAN] Sensor Stopped",
						Activity:    "fogbot is no longer watching its own files for tampering",
						Unit:        "see the fogbot daemon log for the cause; restart with: systemctl restart fogbot",
						Time:        time.Now(),
						Equipment:   "inotify",
						Acknowledge: true,
					})
				}
			}()
			log.Printf("Started selfwatch monitoring")
		}
	}

	// Send startup message
	if notif != nil && authState.IsAnyoneAuthorized() {
		startupAlert := notifier.Alert{
			Severity:  notifier.SeverityNominal,
			Title:     "fogbot online",
			Activity:  fmt.Sprintf("Version %s | %d sensors active", Version, len(registry.Enabled())),
			Host:      machineHostname,
			Time:      time.Now(),
			Equipment: "startup",
		}
		if err := notif.Send(ctx, startupAlert); err != nil {
			log.Printf("Failed to send startup message: %v", err)
		}
	}

	// Start command handler
	if notif != nil {
		cmdChan, err := notif.Commands(ctx)
		if err != nil {
			log.Fatalf("Failed to start command handler: %v", err)
		}

		go handleCommands(ctx, cmdChan, authState, cfg, notif, machineHostname, skillMgr)
	}

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Main event loop
	log.Printf("fogbot daemon running")

	for {
		select {
		case sig := <-sigChan:
			switch sig {
			case syscall.SIGHUP:
				log.Printf("Received SIGHUP, reloading config and skills...")
				if err := cfg.Reload(configPathToUse); err != nil {
					log.Printf("Failed to reload config: %v", err)
				} else {
					log.Printf("Config reloaded successfully")
				}

				// Startup repair must only run what is approved now: pick up
				// approvals revoked by `fogbot skill disable` since startup
				if approvalTracker != nil {
					if err := approvalTracker.Reload(); err != nil {
						log.Printf("Failed to reload approved commands: %v", err)
					}
				}

				configs, err := skills.LoadEnabledConfigs(skills.SkillsEnabledPath)
				if err != nil {
					log.Printf("Failed to load enabled skills, keeping current watchers: %v", err)
					break
				}
				res := skillMgr.apply(configs)
				log.Printf("Skills reloaded: %s", res)
				if res.changed() {
					// A sensor going off is worth a look even when it was the
					// operator: it is also how an intruder would blind fogbot
					severity := notifier.SeverityNominal
					if len(res.stopped)+len(res.failed) > 0 {
						severity = notifier.SeverityMovement
					}
					skillMgr.send(notifier.Alert{
						Severity:  severity,
						Title:     "fogbot skills reloaded",
						Activity:  res.String(),
						Time:      time.Now(),
						Equipment: "reload",
					})
				}

			case syscall.SIGINT, syscall.SIGTERM:
				log.Printf("Received %s, shutting down...", sig)

				// Send shutdown message
				if notif != nil && authState.IsAnyoneAuthorized() {
					shutdownAlert := notifier.Alert{
						Severity:  notifier.SeverityMovement,
						Title:     "fogbot offline",
						Activity:  "Graceful shutdown",
						Host:      machineHostname,
						Time:      time.Now(),
						Equipment: "shutdown",
					}
					_ = notif.Send(ctx, shutdownAlert)
				}

				cancel()
				if notif != nil {
					notif.Close()
				}
				log.Printf("Shutdown complete")
				return
			}

		case <-ctx.Done():
			return
		}
	}
}

func handleCommands(ctx context.Context, cmdChan <-chan notifier.Command, authState *auth.State, cfg *config.Config, notif notifier.Notifier, machineHostname string, skillMgr *skillManager) {
	for {
		select {
		case <-ctx.Done():
			return

		case cmd, ok := <-cmdChan:
			if !ok {
				return
			}

			// Log all commands
			log.Printf("Command from %s: %s", cmd.ChatID, cmd.Verb)

			// Handle commands
			switch cmd.Verb {
			case notifier.CmdStart:
				handleStart(ctx, cmd, authState, notif)

			case "help":
				handleHelp(ctx, cmd, authState, notif)

			case "reset":
				handleReset(ctx, cmd, authState, notif, cfg)

			case notifier.CmdHi, notifier.CmdHello:
				if authState.IsAuthorized(cmd.ChatID) {
					handlePing(ctx, cmd, machineHostname, notif)
				}

			case notifier.CmdStatus:
				if authState.IsAuthorized(cmd.ChatID) {
					handleStatus(ctx, cmd, machineHostname, notif, skillMgr.runningNames())
				}

			case notifier.CmdAck:
				// Only the authorized chat's presses of a signed button get here
				if authState.IsAuthorized(cmd.ChatID) && len(cmd.Args) > 1 {
					log.Printf("Alert from skill #%s acknowledged by chat %s", cmd.Args[1], cmd.ChatID)
				}

			case notifier.CmdApprove:
				if authState.IsAuthorized(cmd.ChatID) {
					handleApprove(ctx, cmd, notif)
				}

			default:
				// Check if this chat is waiting for an auth code
				if authState.IsPendingAuth(cmd.ChatID) {
					// Check if any part of the message contains a valid auth code
					for _, word := range cmd.Args {
						code := strings.ToUpper(word)
						if auth.ValidateCode(code) && handleAuthCodeReceived(ctx, cmd.ChatID, code, authState, notif) {
							break
						}
					}
					// If no valid code found, remind them (but don't spam - only on first few messages)
					// For now, we'll let them figure it out or use /help
				}
				// Otherwise, ignore silently (unauthorized chat)
			}
		}
	}
}

// sendSimpleMessage sends a plain text message back to the chat
func sendSimpleMessage(ctx context.Context, notif notifier.Notifier, chatID, message string) {
	// Type assert to access Telegram-specific methods
	if tg, ok := notif.(*telegram.Telegram); ok {
		if err := tg.SendText(ctx, chatID, message); err != nil {
			log.Printf("Failed to send text to %s: %v", chatID, err)
		}
	} else {
		log.Printf("Notifier doesn't support text messages, chatID=%s", chatID)
	}
}

func handleStart(ctx context.Context, cmd notifier.Command, authState *auth.State, notif notifier.Notifier) {
	log.Printf("handleStart: chatID=%s, args=%v", cmd.ChatID, cmd.Args)

	// If already authorized, send confirmation
	if authState.IsAuthorized(cmd.ChatID) {
		log.Printf("Chat %s already authorized", cmd.ChatID)
		sendSimpleMessage(ctx, notif, cmd.ChatID, "✅ You are already authorized!\n\nAvailable commands:\n• /help - Show all commands\n• /status - System status\n• /reset - Deauthorize this chat\n• hi / hello - Test connection")
		return
	}

	// Only one chat can be paired. Ignore strangers rather than confirm the bot
	// guards a host; the operator re-pairs with /reset from the paired chat.
	if authState.IsAnyoneAuthorized() {
		log.Printf("Ignoring /start from chat %s: another chat is already authorized", cmd.ChatID)
		return
	}

	code := authState.CodeForStart()
	log.Printf("Authorization code generated for chat %s: %s", cmd.ChatID, code)
	log.Printf("*** AUTH CODE: %s ***", code)

	// Mark this chat as waiting for auth code
	authState.MarkPendingAuth(cmd.ChatID)
	log.Printf("Chat %s marked as pending authorization", cmd.ChatID)

	// "/start FOG-XXXX-XXXX" pairs straight away, as the help text's format
	// suggests, rather than ignoring the code and asking for it again
	for _, word := range cmd.Args[1:] {
		if c := strings.ToUpper(word); auth.ValidateCode(c) && handleAuthCodeReceived(ctx, cmd.ChatID, c, authState, notif) {
			return
		}
	}

	// Send instructions
	sendSimpleMessage(ctx, notif, cmd.ChatID, "🔐 *Authorization Required*\n\n"+
		"Please enter the authorization code shown in your fogbot daemon logs.\n\n"+
		"*Format:* `FOG-XXXX-XXXX`\n\n"+
		"Just paste the code in your next message.\n\n"+
		"Type /help for more information.")
}

// handleAuthCodeReceived pairs the chat if code is the current pairing code,
// and reports whether it was
func handleAuthCodeReceived(ctx context.Context, chatID, code string, authState *auth.State, notif notifier.Notifier) bool {
	ok, err := authState.RedeemCode(chatID, code)
	if !ok {
		return false
	}
	log.Printf("Valid auth code received from chat %s", chatID)
	if err != nil {
		log.Printf("Failed to authorize %s: %v", chatID, err)
		sendSimpleMessage(ctx, notif, chatID, "❌ Authorization failed. Please try again or type /start")
		return true
	}

	// Clear pending status
	authState.ClearPendingAuth(chatID)

	log.Printf("Chat %s authorized successfully", chatID)

	// Send success message
	sendSimpleMessage(ctx, notif, chatID, "✅ *Authorization Successful!*\n\n"+
		"You can now use fogbot commands:\n"+
		"• /help - Show all commands\n"+
		"• /status - System status\n"+
		"• hi / hello - Test connection\n"+
		"• /reset - Deauthorize this chat")
	return true
}

func handleHelp(ctx context.Context, cmd notifier.Command, authState *auth.State, notif notifier.Notifier) {
	isAuth := authState.IsAuthorized(cmd.ChatID)
	isPending := authState.IsPendingAuth(cmd.ChatID)

	var helpText string

	if isAuth {
		helpText = "📚 *fogbot Help* (Authorized)\n\n" +
			"*Available Commands:*\n" +
			"• /help - Show this help message\n" +
			"• /status - View system status\n" +
			"• /reset - Deauthorize this chat\n" +
			"• hi / hello - Test connection\n" +
			"\nBaselines are approved on the host: sudo fogbot baseline approve\n\n" +
			"*About:*\n" +
			"fogbot monitors your Linux system for intrusions and reports alerts via Telegram.\n\n" +
			"More info: github.com/penguinpowernz/fogbot"
	} else if isPending {
		helpText = "📚 *fogbot Help* (Waiting for Auth)\n\n" +
			"Please enter your authorization code to continue.\n\n" +
			"*Format:* `FOG-XXXX-XXXX`\n\n" +
			"The code is displayed in your fogbot daemon logs when it starts.\n\n" +
			"Just paste the code in your next message."
	} else {
		helpText = "📚 *fogbot Help*\n\n" +
			"To get started, type /start and follow the instructions.\n\n" +
			"*About:*\n" +
			"fogbot monitors Linux systems for intrusions and reports alerts via Telegram.\n\n" +
			"More info: github.com/penguinpowernz/fogbot"
	}

	sendSimpleMessage(ctx, notif, cmd.ChatID, helpText)
}

func handleReset(ctx context.Context, cmd notifier.Command, authState *auth.State, notif notifier.Notifier, cfg *config.Config) {
	// Only authorized chats can reset
	if !authState.IsAuthorized(cmd.ChatID) {
		sendSimpleMessage(ctx, notif, cmd.ChatID, "❌ You are not authorized.\n\nType /start to begin authorization.")
		return
	}

	log.Printf("Deauthorizing chat %s", cmd.ChatID)

	// Deauthorize
	if err := authState.Deauthorize(); err != nil {
		log.Printf("Failed to deauthorize: %v", err)
		sendSimpleMessage(ctx, notif, cmd.ChatID, "❌ Failed to reset authorization.")
		return
	}

	// Clear any pending states
	authState.ClearPendingAuth(cmd.ChatID)

	log.Printf("Chat %s deauthorized successfully", cmd.ChatID)

	sendSimpleMessage(ctx, notif, cmd.ChatID, "🔄 *Authorization Reset*\n\n"+
		"This chat has been deauthorized.\n\n"+
		"Type /start to generate a new authorization code.")
}

func handlePing(ctx context.Context, cmd notifier.Command, machineHostname string, notif notifier.Notifier) {
	log.Printf("Ping from authorized chat %s", cmd.ChatID)
	uptime := time.Since(daemonStartTime)
	msg := fmt.Sprintf("🟢 fogbot online\n\nHost: %s\nUptime: %s", machineHostname, uptime.Round(time.Second))
	sendSimpleMessage(ctx, notif, cmd.ChatID, msg)
}

func handleStatus(ctx context.Context, cmd notifier.Command, machineHostname string, notif notifier.Notifier, running []string) {
	log.Printf("Status request from %s", cmd.ChatID)
	// Report what is actually running: a sensor that failed to start must not
	// look healthy to the operator
	skillList := "none"
	if len(running) > 0 {
		skillList = strings.Join(running, ", ")
	}
	msg := fmt.Sprintf("📊 Status Report\n\nHost: %s\nUptime: %s\nSkills running (%d): %s",
		machineHostname, time.Since(daemonStartTime).Round(time.Second), len(running), skillList)
	sendSimpleMessage(ctx, notif, cmd.ChatID, msg)
}

func handleApprove(ctx context.Context, cmd notifier.Command, notif notifier.Notifier) {
	// Approving over Telegram would let whoever holds the authorized chat
	// whitelist a planted SUID binary, so it must be done on the host as root.
	sendSimpleMessage(ctx, notif, cmd.ChatID, "Baselines can't be approved over Telegram.\n\n"+
		"On the host, review and approve with:\n"+
		"  sudo fogbot baseline diff\n"+
		"  sudo fogbot baseline approve")
}

// processAlerts passes alerts from the bus through dedup and queues them for
// sending. Without a notifier alerts are only logged, but the bus is still
// drained so watchers never block.
//
// Sending happens on its own goroutine. When it happened here, one alert
// waiting out Telegram's rate limit (up to three minutes of retries) stopped
// the bus: watchers blocked, and the audit tailer threw away the events it
// couldn't hand them. Anyone able to set off a burst of alerts could get the
// events that followed dropped.
func processAlerts(ctx context.Context, bus <-chan notifier.Alert, dedupEngine *dedup.Engine, notif notifier.Notifier, hostname string) {
	// Suppressed alerts are only reported through these digests
	digestTicker := time.NewTicker(digestInterval)
	defer digestTicker.Stop()

	out := newAlertQueue(notif)
	if notif != nil {
		go out.run(ctx)
	}

	for {
		select {
		case <-ctx.Done():
			return

		case now := <-digestTicker.C:
			for _, digest := range dedupEngine.Digests(now) {
				deliverAlert(digest, out, hostname)
			}

		case alert := <-bus:
			shouldSend, isDigest, digestCount := dedupEngine.Process(alert)
			if !shouldSend {
				log.Printf("[alert-suppressed] %s: %s (dedup)", alert.Severity, alert.Title)
				continue
			}

			if isDigest {
				alert.Title = fmt.Sprintf("%s (digest: %d events)", alert.Title, digestCount)
			}
			deliverAlert(alert, out, hostname)
		}
	}
}

// digestInterval is how often processAlerts checks for CONTACT digests that
// are due
const digestInterval = 10 * time.Second

// deliverAlert logs an alert and queues it for sending
func deliverAlert(alert notifier.Alert, out *alertQueue, hostname string) {
	if alert.Host == "" {
		alert.Host = hostname
	}
	log.Printf("[alert] %s: %s - %s", alert.Severity, alert.Title, alert.Activity)
	out.add(alert)
}

// alertQueueSize bounds how many alerts can wait to be sent. Dedup keeps a
// flood well below it; it only fills if Telegram is unreachable for long.
const alertQueueSize = 500

// alertQueue holds alerts waiting to be sent, so a slow send never holds up
// the alert bus
type alertQueue struct {
	notif   notifier.Notifier
	queue   chan notifier.Alert
	dropped atomic.Int64 // alerts that didn't fit in the queue
}

func newAlertQueue(notif notifier.Notifier) *alertQueue {
	return &alertQueue{notif: notif, queue: make(chan notifier.Alert, alertQueueSize)}
}

// add queues an alert without blocking. One that doesn't fit is counted, and
// the count is reported once the queue drains.
func (q *alertQueue) add(alert notifier.Alert) {
	if q.notif == nil {
		return
	}
	select {
	case q.queue <- alert:
	default:
		q.dropped.Add(1)
		log.Printf("[alert-dropped] %s: %s (send queue full)", alert.Severity, alert.Title)
	}
}

// run sends queued alerts until ctx ends
func (q *alertQueue) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case alert := <-q.queue:
			q.send(ctx, alert)
			if n := q.dropped.Swap(0); n > 0 {
				q.send(ctx, notifier.Alert{
					Severity:    notifier.SeverityContact,
					Title:       "Alerts Dropped",
					Size:        fmt.Sprintf("%d alerts", n),
					Activity:    fmt.Sprintf("%d alerts could not be sent: too many were waiting while Telegram was slow or unreachable", n),
					Unit:        "the dropped alerts are in the fogbot daemon log as [alert-dropped]",
					Host:        alert.Host,
					Time:        time.Now(),
					Equipment:   "alert-queue",
					Acknowledge: true,
				})
			}
		}
	}
}

func (q *alertQueue) send(ctx context.Context, alert notifier.Alert) {
	if err := q.notif.Send(ctx, alert); err != nil {
		log.Printf("Failed to send alert: %v", err)
	}
}
