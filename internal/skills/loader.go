package skills

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	SkillsAvailablePath = getEnvOrDefault("FOGBOT_SKILLS_AVAILABLE", "/etc/fogbot/skills-available")
	SkillsEnabledPath   = getEnvOrDefault("FOGBOT_SKILLS_ENABLED", "/etc/fogbot/skills-enabled")
)

func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// LoadAvailable reads all skill YAML files from skills-available directory
func LoadAvailable(basePath string) ([]SkillConfig, error) {
	if basePath == "" {
		basePath = SkillsAvailablePath
	}

	entries, err := os.ReadDir(basePath)
	if err != nil {
		if os.IsNotExist(err) {
			return []SkillConfig{}, nil
		}
		return nil, fmt.Errorf("reading skills-available: %w", err)
	}

	var configs []SkillConfig
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}

		path := filepath.Join(basePath, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}

		var cfg SkillConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}

		configs = append(configs, cfg)
	}

	// Sort by ID
	sort.Slice(configs, func(i, j int) bool {
		return configs[i].ID < configs[j].ID
	})

	return configs, nil
}

// LoadEnabled reads symlinks from skills-enabled directory
// Returns the set of enabled skill IDs
func LoadEnabled(basePath string) (map[int]bool, error) {
	if basePath == "" {
		basePath = SkillsEnabledPath
	}

	enabled := make(map[int]bool)

	entries, err := os.ReadDir(basePath)
	if err != nil {
		if os.IsNotExist(err) {
			return enabled, nil
		}
		return nil, fmt.Errorf("reading skills-enabled: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}

		path := filepath.Join(basePath, entry.Name())

		// Check if it's a symlink
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink == 0 {
			// Not a symlink, skip
			continue
		}

		// Read the YAML to get the ID
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var cfg SkillConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			continue
		}

		enabled[cfg.ID] = true
	}

	return enabled, nil
}

// IsEnabled checks if a skill is enabled by checking for symlink in skills-enabled
func IsEnabled(skillName string, basePath string) bool {
	if basePath == "" {
		basePath = SkillsEnabledPath
	}

	// Check exact match first
	linkPath := filepath.Join(basePath, skillName+".yaml")
	info, err := os.Lstat(linkPath)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return true
	}

	// Check for files matching the pattern (e.g., 200-suid-sweep.yaml for "suid-sweep")
	entries, err := os.ReadDir(basePath)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Check if it ends with -skillName.yaml
		if strings.HasSuffix(name, "-"+skillName+".yaml") {
			info, err := os.Lstat(filepath.Join(basePath, name))
			if err == nil && info.Mode()&os.ModeSymlink != 0 {
				return true
			}
		}
		// Check if it contains the skill name
		if strings.Contains(name, skillName) && filepath.Ext(name) == ".yaml" {
			info, err := os.Lstat(filepath.Join(basePath, name))
			if err == nil && info.Mode()&os.ModeSymlink != 0 {
				return true
			}
		}
	}

	return false
}

// Enable creates a symlink in skills-enabled pointing to skills-available
func Enable(skillName string, availablePath, enabledPath string) error {
	if availablePath == "" {
		availablePath = SkillsAvailablePath
	}
	if enabledPath == "" {
		enabledPath = SkillsEnabledPath
	}

	// Ensure skills-enabled directory exists
	if err := os.MkdirAll(enabledPath, 0755); err != nil {
		return fmt.Errorf("creating skills-enabled dir: %w", err)
	}

	// Find the actual file (may have numeric prefix like 100-ssh-monitor.yaml)
	var sourcePath string
	entries, err := os.ReadDir(availablePath)
	if err != nil {
		return fmt.Errorf("reading skills-available: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// Match files ending with skillName.yaml or containing skillName
		name := entry.Name()
		if name == skillName+".yaml" {
			sourcePath = filepath.Join(availablePath, name)
			break
		}
		// Check if it ends with -skillName.yaml (e.g., 410-service-health.yaml)
		if filepath.Ext(name) == ".yaml" && strings.HasSuffix(name, "-"+skillName+".yaml") {
			sourcePath = filepath.Join(availablePath, name)
			break
		}
		// Check if it contains the skill name (e.g., 410-service-health.yaml matches "service-health")
		if filepath.Ext(name) == ".yaml" && strings.Contains(name, skillName) {
			sourcePath = filepath.Join(availablePath, name)
			break
		}
	}

	if sourcePath == "" {
		return fmt.Errorf("skill %s not found in skills-available", skillName)
	}

	// Use the same filename for the symlink
	sourceFileName := filepath.Base(sourcePath)
	linkPath := filepath.Join(enabledPath, sourceFileName)

	// Check if already enabled
	if _, err := os.Lstat(linkPath); err == nil {
		return fmt.Errorf("skill %s is already enabled", skillName)
	}

	// Create relative symlink
	relPath, err := filepath.Rel(enabledPath, sourcePath)
	if err != nil {
		return fmt.Errorf("calculating relative path: %w", err)
	}

	if err := os.Symlink(relPath, linkPath); err != nil {
		return fmt.Errorf("creating symlink: %w", err)
	}

	return nil
}

// LoadEnabledConfigs reads and parses all enabled skill configurations
func LoadEnabledConfigs(basePath string) ([]SkillConfig, error) {
	if basePath == "" {
		basePath = SkillsEnabledPath
	}

	var configs []SkillConfig

	entries, err := os.ReadDir(basePath)
	if err != nil {
		if os.IsNotExist(err) {
			return configs, nil
		}
		return nil, fmt.Errorf("reading skills-enabled: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}

		path := filepath.Join(basePath, entry.Name())

		// Check if it's a symlink
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink == 0 {
			// Not a symlink, skip
			continue
		}

		// Read and parse the YAML
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var cfg SkillConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			continue
		}

		configs = append(configs, cfg)
	}

	// Sort by ID
	sort.Slice(configs, func(i, j int) bool {
		return configs[i].ID < configs[j].ID
	})

	return configs, nil
}

// Disable removes the symlink from skills-enabled
func Disable(skillName string, enabledPath string) error {
	if enabledPath == "" {
		enabledPath = SkillsEnabledPath
	}

	// Find the actual symlink (may have numeric prefix)
	var linkPath string
	entries, err := os.ReadDir(enabledPath)
	if err != nil {
		return fmt.Errorf("reading skills-enabled: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == skillName+".yaml" {
			linkPath = filepath.Join(enabledPath, name)
			break
		}
		// Check if it ends with -skillName.yaml
		if filepath.Ext(name) == ".yaml" && strings.HasSuffix(name, "-"+skillName+".yaml") {
			linkPath = filepath.Join(enabledPath, name)
			break
		}
		// Check if it contains the skill name
		if filepath.Ext(name) == ".yaml" && strings.Contains(name, skillName) {
			linkPath = filepath.Join(enabledPath, name)
			break
		}
	}

	if linkPath == "" {
		return fmt.Errorf("skill %s is not enabled", skillName)
	}

	// Check if it exists and is a symlink
	info, err := os.Lstat(linkPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("skill %s is not enabled", skillName)
		}
		return fmt.Errorf("checking symlink: %w", err)
	}

	if info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("skills-enabled/%s is not a symlink", filepath.Base(linkPath))
	}

	if err := os.Remove(linkPath); err != nil {
		return fmt.Errorf("removing symlink: %w", err)
	}

	return nil
}
