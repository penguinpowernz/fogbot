package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"sync"

	"github.com/penguinpowernz/fogbot/internal/auth"
	"github.com/penguinpowernz/fogbot/internal/baseline"
	"github.com/penguinpowernz/fogbot/internal/config"
	"github.com/penguinpowernz/fogbot/internal/dedup"
	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/notifier/telegram"
	"github.com/penguinpowernz/fogbot/internal/selfwatch"
	"github.com/penguinpowernz/fogbot/internal/skills"
	"github.com/penguinpowernz/fogbot/internal/skills/auditdhealth"
	"github.com/penguinpowernz/fogbot/internal/skills/dirwatch"
	"github.com/penguinpowernz/fogbot/internal/skills/logfreshness"
	"github.com/penguinpowernz/fogbot/internal/skills/pkgmonitor"
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
	// dryRun defaults to false or env "true" - Cobra handles --dry-run=dry from CLI
}

func main() {
	// Initialize flag values from environment variables or defaults
	initFlagsFromEnv()

	rootCmd := &cobra.Command{
		Use:   "fogbot",
		Short: "Linux intrusion detection via Telegram",
		Long:  "A Go daemon that monitors detection subsystems and reports anomalies via Telegram",
	}

	// Add global flags - available to ALL commands, not just daemon
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "Path to config file (default: $FOGBOT_CONFIG)")
	rootCmd.PersistentFlags().StringVarP(&stateDir, "state-dir", "s", "", "State directory (default: $FOGBOT_STATE_DIR)")
	rootCmd.PersistentFlags().StringVar(&skillsAvailable, "skills-available", "", "Skills available directory (default: $FOGBOT_SKILLS_AVAILABLE)")
	rootCmd.PersistentFlags().StringVar(&skillsEnabled, "skills-enabled", "", "Skills enabled directory (default: $FOGBOT_SKILLS_ENABLED)")
	rootCmd.PersistentFlags().StringVar(&hostLabel, "host-label", "", "Host label for alerts (default: $FOGBOT_HOST_LABEL or hostname)")
	rootCmd.PersistentFlags().BoolVarP(&dryRun, "dry-run", "d", false, "Dry-run mode - no system modifications ($FOGBOT_DRY_RUN)")

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
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	})

	// Add CLI subcommands (to be implemented) - now have access to global flags
	rootCmd.AddCommand(newSkillCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runDaemon(cmd *cobra.Command, args []string) {
	log.Printf("fogbot %s starting...", Version)

	// Build config path (CLI flag overrides env var)
	configPathToUse := configPath
	if configPathToUse == "" {
		configPathToUse = config.DefaultConfigPath
	}

	// Build state dir (CLI flag overrides env var)
	stateDirToUse := stateDir
	if stateDirToUse == "" {
		stateDirToUse = config.DefaultStateDir
	}

	// Get real machine hostname for alerts (always use actual hostname, never from config file)
	machineHostname, _ := os.Hostname()

	// Load config
	cfg, err := config.Load(configPathToUse)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Config file not found, using defaults")
			cfg = &config.Config{}
			cfg.StateDir = stateDirToUse
		} else {
			log.Fatalf("Failed to load config: %v", err)
		}
	}

	// Override state dir with CLI flag if provided
	if stateDirToUse != "" {
		cfg.StateDir = stateDirToUse
	}

	// Create state directory
	if err := os.MkdirAll(cfg.StateDir, 0755); err != nil {
		log.Fatalf("Failed to create state directory: %v", err)
	}

	// Initialize auth state
	statePath := filepath.Join(cfg.StateDir, "state.json")
	authState, err := auth.NewState(statePath)
	if err != nil {
		log.Fatalf("Failed to initialize auth state: %v", err)
	}

	// Check authorization status
	if authState.IsAuthorized("") {
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
	dedupEngine := dedup.NewEngine(cfg.Dedup.Window, cfg.Dedup.MaxBurst)
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
	registry.Register(dirwatch.New())

	// Log registered skills
	log.Printf("Skill registry initialized with %d skills:", len(registry.All()))
	for _, skill := range registry.All() {
		log.Printf("  - #%d: %s", skill.ID(), skill.Name())
	}

	// Build skills directories (CLI flags override env vars)
	skillsAvailToUse := skillsAvailable
	if skillsAvailToUse == "" {
		skillsAvailToUse = os.Getenv("FOGBOT_SKILLS_AVAILABLE")
	}

	skillsEnabToUse := skillsEnabled
	if skillsEnabToUse == "" {
		skillsEnabToUse = os.Getenv("FOGBOT_SKILLS_ENABLED")
	}

	// Override skills package paths so all functions use the correct directories
	skills.OverrideSkillsPaths(skillsAvailToUse, skillsEnabToUse)

	// Load enabled skills from filesystem
	log.Printf("Loading enabled skills from: %s", skillsEnabToUse)
	enabledSkillConfigs, err := skills.LoadEnabledConfigs(skillsEnabToUse)
	if err != nil {
		log.Fatalf("Failed to load enabled skills: %v", err)
	}
	log.Printf("Found %d enabled skill configs", len(enabledSkillConfigs))

	// Configure and enable skills based on loaded configs
	for _, skillCfg := range enabledSkillConfigs {
		log.Printf("Loading skill #%d (%s) from config file", skillCfg.ID, skillCfg.Name)
		skill, ok := registry.Get(skillCfg.ID)
		if !ok {
			log.Printf("Warning: skill %d (%s) enabled but not in registry", skillCfg.ID, skillCfg.Name)
			continue
		}

		if err := skill.Configure(skillCfg.Config); err != nil {
			log.Printf("Failed to configure skill %s: %v", skillCfg.Name, err)
			continue
		}

		skill.SetEnabled(true)
		log.Printf("✓ Enabled skill #%d: %s", skillCfg.ID, skillCfg.Name)
	}

	// Start all enabled skills
	alertChannels := make([]<-chan notifier.Alert, 0)
	for _, skill := range registry.Enabled() {
		alertChan, err := skill.Watch(ctx)
		if err != nil {
			log.Printf("Failed to start skill %s: %v", skill.Name(), err)
			continue
		}
		alertChannels = append(alertChannels, alertChan)
		log.Printf("Started watcher for skill #%d: %s", skill.ID(), skill.Name())
	}

	// Start selfwatch to monitor fogbot's own files
	binaryPath, _ := os.Executable()
	sw, err := selfwatch.New(binaryPath, configPathToUse, cfg.StateDir)
	if err != nil {
		log.Printf("Failed to create selfwatch: %v", err)
	} else {
		selfwatchChan, err := sw.Watch(ctx, machineHostname)
		if err != nil {
			log.Printf("Failed to start selfwatch: %v", err)
		} else {
			alertChannels = append(alertChannels, selfwatchChan)
			log.Printf("Started selfwatch monitoring")
		}
	}

	// Merge all alert channels and process through dedup engine
	if notif != nil {
		go mergeAndSendAlerts(ctx, alertChannels, dedupEngine, notif)
	}

	// Send startup message
	if notif != nil && authState.IsAuthorized("") {
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

		go handleCommands(ctx, cmdChan, authState, cfg, notif, machineHostname)
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
				log.Printf("Received SIGHUP, reloading config...")
				if err := cfg.Reload(configPathToUse); err != nil {
					log.Printf("Failed to reload config: %v", err)
				} else {
					log.Printf("Config reloaded successfully")
				}

			case syscall.SIGINT, syscall.SIGTERM:
				log.Printf("Received %s, shutting down...", sig)

				// Send shutdown message
				if notif != nil && authState.IsAuthorized("") {
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

func handleCommands(ctx context.Context, cmdChan <-chan notifier.Command, authState *auth.State, cfg *config.Config, notif notifier.Notifier, machineHostname string) {
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
					handleStatus(ctx, cmd, machineHostname, notif)
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
						if auth.ValidateCode(code) && authState.VerifyCode(code) {
							// Found valid code! Authorize
							handleAuthCodeReceived(ctx, cmd.ChatID, code, authState, notif)
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

	// Generate new auth code
	code := authState.GenerateNewCode()
	log.Printf("Authorization code generated for chat %s: %s", cmd.ChatID, code)
	log.Printf("*** AUTH CODE: %s ***", code)

	// Mark this chat as waiting for auth code
	authState.MarkPendingAuth(cmd.ChatID)
	log.Printf("Chat %s marked as pending authorization", cmd.ChatID)

	// Send instructions
	sendSimpleMessage(ctx, notif, cmd.ChatID, "🔐 *Authorization Required*\n\n"+
		"Please enter the authorization code shown in your fogbot daemon logs.\n\n"+
		"*Format:* `FOG-XXXX-XXXX`\n\n"+
		"Just paste the code in your next message.\n\n"+
		"Type /help for more information.")
}

func handleAuthCodeReceived(ctx context.Context, chatID, code string, authState *auth.State, notif notifier.Notifier) {
	log.Printf("Valid auth code received from chat %s", chatID)

	// Authorize the chat
	if err := authState.Authorize(chatID); err != nil {
		log.Printf("Failed to authorize %s: %v", chatID, err)
		sendSimpleMessage(ctx, notif, chatID, "❌ Authorization failed. Please try again or type /start")
		return
	}

	// Clear pending status
	authState.ClearPendingAuth(chatID)

	// Update the Telegram notifier's chatID so future alerts work
	if tg, ok := notif.(*telegram.Telegram); ok {
		if err := tg.UpdateChatID(chatID); err != nil {
			log.Printf("Failed to update Telegram chatID: %v", err)
		}
	}

	log.Printf("Chat %s authorized successfully", chatID)

	// Send success message
	sendSimpleMessage(ctx, notif, chatID, "✅ *Authorization Successful!*\n\n"+
		"You can now use fogbot commands:\n"+
		"• /help - Show all commands\n"+
		"• /status - System status\n"+
		"• hi / hello - Test connection\n"+
		"• /reset - Deauthorize this chat")
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
			"• /approve - Approve pending baselines\n\n" +
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
	uptime := time.Since(time.Now()) // TODO: track actual start time
	msg := fmt.Sprintf("🟢 fogbot online\n\nHost: %s\nUptime: %s", machineHostname, uptime)
	sendSimpleMessage(ctx, notif, cmd.ChatID, msg)
}

func handleStatus(ctx context.Context, cmd notifier.Command, machineHostname string, notif notifier.Notifier) {
	log.Printf("Status request from %s", cmd.ChatID)
	msg := fmt.Sprintf("📊 Status Report\n\nHost: %s\nSkills enabled: 0\nAlerts: 0 🔴 0 🟡\n\n(Full status coming in Phase 3)", machineHostname)
	sendSimpleMessage(ctx, notif, cmd.ChatID, msg)
}

func handleApprove(ctx context.Context, cmd notifier.Command, notif notifier.Notifier) {
	log.Printf("Approve command from authorized chat")
	sendSimpleMessage(ctx, notif, cmd.ChatID, "✅ Baseline approved\n\n(Full approval flow coming in Phase 2)")
}

// mergeAndSendAlerts merges all skill alert channels and sends them via the notifier
func mergeAndSendAlerts(ctx context.Context, alertChannels []<-chan notifier.Alert, dedupEngine *dedup.Engine, notif notifier.Notifier) {
	// Create a merged channel using fan-in pattern
	merged := make(chan notifier.Alert)
	var wg sync.WaitGroup

	// Start goroutine for each input channel
	for _, ch := range alertChannels {
		wg.Add(1)
		go func(c <-chan notifier.Alert) {
			defer wg.Done()
			for {
				select {
				case alert, ok := <-c:
					if !ok {
						return // channel closed
					}
					select {
					case merged <- alert:
					case <-ctx.Done():
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}(ch)
	}

	// Close merged channel when all inputs are done
	go func() {
		wg.Wait()
		close(merged)
	}()

	// Process merged alerts
	for {
		select {
		case <-ctx.Done():
			return

		case alert, ok := <-merged:
			if !ok {
				// All channels closed
				return
			}

			// Pass through dedup engine
			shouldSend, isDigest, digestCount := dedupEngine.Process(alert)

			if shouldSend {
				// Modify alert if it's a digest
				if isDigest {
					alert.Title = fmt.Sprintf("%s (digest: %d events)", alert.Title, digestCount)
				}

				log.Printf("[alert] %s: %s - %s", alert.Severity, alert.Title, alert.Activity)

				if err := notif.Send(ctx, alert); err != nil {
					log.Printf("Failed to send alert: %v", err)
				}
			} else {
				log.Printf("[alert-suppressed] %s: %s (dedup)", alert.Severity, alert.Title)
			}
		}
	}
}
