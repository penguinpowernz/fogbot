package skills

import (
	"context"

	"github.com/penguinpowernz/fogbot/internal/notifier"
)

// SkillConfig holds the parsed YAML configuration for a skill
type SkillConfig struct {
	ID              int                    `yaml:"id"`
	Name            string                 `yaml:"name"`
	Description     string                 `yaml:"description"`
	Why             string                 `yaml:"why"`
	Requires        []string               `yaml:"requires"`
	Tags            []string               `yaml:"tags"`
	SeverityDefault string                 `yaml:"severity_default"`
	Config          map[string]interface{} `yaml:"config"`
}

// DropIn represents a system configuration file managed by a skill
type DropIn struct {
	Path    string // absolute path to drop-in file
	Content string // file contents
}

// Skill is the unit of detection capability
type Skill interface {
	// ID returns the numeric skill identifier
	ID() int

	// Name returns the machine name (e.g. "port-tripwires")
	Name() string

	// Description returns a human summary
	Description() string

	// Why explains the security value of this skill
	Why() string

	// Requires returns dependencies (e.g. ["iptables", "root", "auditd"])
	Requires() []string

	// Tags returns categorization tags
	Tags() []string

	// DropIns returns the drop-in config files this skill manages
	DropIns() []DropIn

	// Configure writes drop-ins and prepares the skill for watching
	Configure(cfg map[string]interface{}) error

	// Watch starts the detection loop, returning alerts on the channel
	Watch(ctx context.Context) (<-chan notifier.Alert, error)

	// Enabled returns whether this skill is currently enabled
	Enabled() bool

	// SetEnabled marks the skill as enabled or disabled
	SetEnabled(enabled bool)

	// Config returns the current configuration
	Config() map[string]interface{}
}

// Registry holds all available skills
type Registry struct {
	skills map[int]Skill
}

// NewRegistry creates an empty skill registry
func NewRegistry() *Registry {
	return &Registry{
		skills: make(map[int]Skill),
	}
}

// Register adds a skill to the registry
func (r *Registry) Register(skill Skill) {
	r.skills[skill.ID()] = skill
}

// Get retrieves a skill by ID
func (r *Registry) Get(id int) (Skill, bool) {
	skill, ok := r.skills[id]
	return skill, ok
}

// GetByName retrieves a skill by name
func (r *Registry) GetByName(name string) (Skill, bool) {
	for _, skill := range r.skills {
		if skill.Name() == name {
			return skill, true
		}
	}
	return nil, false
}

// All returns all registered skills
func (r *Registry) All() []Skill {
	result := make([]Skill, 0, len(r.skills))
	for _, skill := range r.skills {
		result = append(result, skill)
	}
	return result
}

// Enabled returns only enabled skills
func (r *Registry) Enabled() []Skill {
	result := make([]Skill, 0)
	for _, skill := range r.skills {
		if skill.Enabled() {
			result = append(result, skill)
		}
	}
	return result
}
