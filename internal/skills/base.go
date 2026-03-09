package skills

import "fmt"

// BaseSkill provides default implementations for skills that don't need them
// Embed this in skills that don't require system configuration changes
type BaseSkill struct{}

// DeduceCommands returns no commands by default
func (b BaseSkill) DeduceCommands(cfg map[string]interface{}) ([]SystemCommand, error) {
	return []SystemCommand{}, nil
}

// CheckSystemState returns true by default (no configuration needed)
func (b BaseSkill) CheckSystemState() (bool, error) {
	return true, nil
}

// LegacySkill wraps old skills that don't implement the new interface methods
type LegacySkill struct {
	Skill
}

// DeduceCommands returns empty for legacy skills
func (l *LegacySkill) DeduceCommands(cfg map[string]interface{}) ([]SystemCommand, error) {
	return []SystemCommand{}, fmt.Errorf("legacy skill does not support command deduction")
}

// CheckSystemState always returns true for legacy skills
func (l *LegacySkill) CheckSystemState() (bool, error) {
	return true, nil
}
