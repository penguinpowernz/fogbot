package config

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

var (
	DefaultConfigPath = getEnvOrDefault("FOGBOT_CONFIG", "/etc/fogbot/config.yaml")
	DefaultStateDir   = getEnvOrDefault("FOGBOT_STATE_DIR", "/var/lib/fogbot")
	DefaultHostLabel  = getEnvOrDefault("FOGBOT_HOST_LABEL", "")
)

func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// atoi64 converts an environment variable string to int64
func atoi64(envVar string) int64 {
	if envVar == "" {
		return 0
	}
	val, err := strconv.ParseInt(envVar, 10, 64)
	if err != nil {
		return 0
	}
	return val
}

// Config represents the fogbot configuration
type Config struct {
	mu sync.RWMutex

	Telegram struct {
		Token  string `yaml:"token"`
		ChatID int64  `yaml:"chat_id"`
	} `yaml:"telegram"`

	HostLabel string `yaml:"host_label"`

	QuietHours struct {
		Enabled bool   `yaml:"enabled"`
		Start   string `yaml:"start"`
		End     string `yaml:"end"`
	} `yaml:"quiet_hours"`

	StatusReport struct {
		Enabled  bool   `yaml:"enabled"`
		Schedule string `yaml:"schedule"` // daily | weekly
		Time     string `yaml:"time"`     // HH:MM 24h format
		Day      string `yaml:"day"`      // for weekly: mon/tue/wed/thu/fri/sat/sun
		Timezone string `yaml:"timezone"` // IANA tz string
	} `yaml:"status_report"`

	Dedup struct {
		Window   time.Duration `yaml:"window"`
		MaxBurst int           `yaml:"max_burst"`
	} `yaml:"dedup"`

	StateDir string `yaml:"state_dir"`

	// Skill-specific configs are stored separately in skill YAMLs
}

// Load reads and parses the config file
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultConfigPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Apply defaults
	cfg.applyDefaults()

	return &cfg, nil
}

// applyDefaults sets default values for unspecified config options
func (c *Config) applyDefaults() {
	if c.HostLabel == "" {
		c.HostLabel = DefaultHostLabel
	}

	if c.StateDir == "" {
		c.StateDir = DefaultStateDir
	}

	if c.Dedup.Window == 0 {
		c.Dedup.Window = 5 * time.Minute
	}

	if c.Dedup.MaxBurst == 0 {
		c.Dedup.MaxBurst = 10
	}

	if c.StatusReport.Schedule == "" {
		c.StatusReport.Schedule = "daily"
	}

	if c.StatusReport.Time == "" {
		c.StatusReport.Time = "09:00"
	}

	if c.StatusReport.Timezone == "" {
		c.StatusReport.Timezone = "UTC"
	}
}

// Save writes the config back to disk
func (c *Config) Save(path string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if path == "" {
		path = DefaultConfigPath
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	return nil
}

// Reload reloads the config from disk
func (c *Config) Reload(path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if path == "" {
		path = DefaultConfigPath
	}

	newCfg, err := Load(path)
	if err != nil {
		return err
	}

	// Copy new values (mutex already held)
	c.Telegram = newCfg.Telegram
	c.HostLabel = newCfg.HostLabel
	c.StateDir = newCfg.StateDir
	c.Dedup = newCfg.Dedup

	return nil
}

// GetHostLabel safely returns the host label (with CLI override support via env check)
func (c *Config) GetHostLabel() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.HostLabel == "" {
		// Check for FOGBOT_HOST_LABEL env var as fallback
		if envLabel := os.Getenv("FOGBOT_HOST_LABEL"); envLabel != "" {
			return envLabel
		}
		hostname, _ := os.Hostname()
		return hostname
	}
	return c.HostLabel
}

// GetTelegramToken safely returns the Telegram token
func (c *Config) GetTelegramToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.Telegram.Token == "" {
		// Fall back to environment variable
		return os.Getenv("FOGBOT_TELEGRAM_TOKEN")
	}
	return c.Telegram.Token
}

// GetTelegramChatID safely returns the Telegram chat ID
func (c *Config) GetTelegramChatID() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.Telegram.ChatID == 0 {
		// Fall back to environment variable
		return atoi64(os.Getenv("FOGBOT_TELEGRAM_CHAT_ID"))
	}
	return c.Telegram.ChatID
}


// IsQuietHours checks if current time is within quiet hours
func (c *Config) IsQuietHours() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.QuietHours.Enabled {
		return false
	}

	// Parse times (simplified - production would handle timezone properly)
	now := time.Now()
	// TODO: implement proper quiet hours check
	_ = now

	return false
}
