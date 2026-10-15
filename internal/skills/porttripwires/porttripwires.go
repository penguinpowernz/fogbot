package porttripwires

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"

	"github.com/kballard/go-shellquote"

	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
)

// PortTripwires monitors unusual network ports for inbound/outbound traffic
type PortTripwires struct {
	id              int
	name            string
	description     string
	why             string
	requires        []string
	tags            []string
	enabled         bool
	config          map[string]interface{}
	severityDefault string

	// iptables runs the iptables command; nil means the real one
	iptables iptablesRunner
}

// New creates a new PortTripwires skill from config
// NewDefault creates a PortTripwires for daemon registration.
// Configure() will be called later with the actual YAML config.
func NewDefault() *PortTripwires {
	return &PortTripwires{
		id:     510,
		name:   "port-tripwires",
		config: map[string]interface{}{},
	}
}

func New(cfg skills.SkillConfig) *PortTripwires {
	return &PortTripwires{
		id:              cfg.ID,
		name:            cfg.Name,
		description:     cfg.Description,
		why:             cfg.Why,
		requires:        cfg.Requires,
		tags:            cfg.Tags,
		config:          cfg.Config,
		severityDefault: cfg.SeverityDefault,
		enabled:         false,
	}
}

func (p *PortTripwires) ID() int                           { return p.id }
func (p *PortTripwires) Name() string                      { return p.name }
func (p *PortTripwires) Description() string               { return p.description }
func (p *PortTripwires) Why() string                       { return p.why }
func (p *PortTripwires) Requires() []string                { return p.requires }
func (p *PortTripwires) Tags() []string                    { return p.tags }
func (p *PortTripwires) Enabled() bool                     { return p.enabled }
func (p *PortTripwires) SetEnabled(enabled bool)           { p.enabled = enabled }
func (p *PortTripwires) Config() map[string]interface{}    { return p.config }
func (p *PortTripwires) DropIns() []skills.DropIn          { return nil }
func (p *PortTripwires) SetupHints() []string              { return nil }

func (p *PortTripwires) Configure(cfg map[string]interface{}) error {
	p.config = cfg
	return nil
}

// generateRuleID creates an identifier based on skill ID and direction
func (p *PortTripwires) generateRuleID(direction string) string {
	// Use fw-<skillID>-<direction> format (e.g., fw-510-in, fw-510-out)
	return fmt.Sprintf("fw-%d-%s", p.id, direction)
}

// iptablesRunner runs iptables with args and returns its stdout
type iptablesRunner func(args ...string) ([]byte, error)

func runIptables(args ...string) ([]byte, error) {
	return exec.Command("iptables", args...).Output()
}

// tripwire describes the LOG rule for one traffic direction
type tripwire struct {
	direction string // rule ID suffix
	chain     string
	configKey string
	label     string
}

var tripwires = []tripwire{
	{"in", "INPUT", "watch_inbound", "inbound"},
	{"out", "OUTPUT", "watch_outbound", "outbound"},
}

// queryError marks a failure to read the current iptables rules, as opposed to
// a bad config
type queryError struct{ err error }

func (e queryError) Error() string { return fmt.Sprintf("failed to check iptables: %v", e.err) }
func (e queryError) Unwrap() error { return e.err }

// DeduceCommands generates the iptables commands that bring the system in line
// with the declarative config: removing tripwire rules left over from an
// earlier port list, and adding the rule for the current one.
func (p *PortTripwires) DeduceCommands(cfg map[string]interface{}) ([]skills.SystemCommand, error) {
	commands, err := p.plan(cfg, true)
	var qe queryError
	if errors.As(err, &qe) {
		// Only reachable when the rules can't be read at all (e.g. a dry run
		// without root); CheckSystemState fails first in a real run
		log.Printf("[port-tripwires] %v; listing add commands only", err)
		return p.plan(cfg, false)
	}
	return commands, err
}

// CheckSystemState reports whether each chain holds exactly the tripwire rule
// the config calls for. Checking only for the rule ID would miss a changed port
// list, so the new ports would never be applied.
func (p *PortTripwires) CheckSystemState() (bool, error) {
	commands, err := p.plan(p.config, true)
	if err != nil {
		return false, err
	}
	return len(commands) == 0, nil
}

// plan compares the tripwire rules in each chain against the config and
// returns the commands needed to reconcile them. With inspect false the
// current rules aren't read and only the add commands are returned.
func (p *PortTripwires) plan(cfg map[string]interface{}, inspect bool) ([]skills.SystemCommand, error) {
	commands := []skills.SystemCommand{}

	for _, tw := range tripwires {
		ports, err := extractPorts(cfg, tw.configKey)
		if err != nil {
			return nil, fmt.Errorf("invalid %s config: %w", tw.configKey, err)
		}

		ruleID := p.generateRuleID(tw.direction)

		var add *skills.SystemCommand
		var want []string // the rule as iptables -S prints it
		if len(ports) > 0 {
			portList := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(ports)), ","), "[]")
			cmd := fmt.Sprintf(
				"iptables -A %s -p tcp -m multiport --dports %s -j LOG --log-prefix '%s: '",
				tw.chain, portList, ruleID,
			)
			add = &skills.SystemCommand{
				Command:     cmd,
				Description: fmt.Sprintf("Monitor %s traffic on ports: %s", tw.label, portList),
				Metadata: map[string]string{
					"rule_id":   ruleID,
					"direction": tw.direction,
					"ports":     portList,
				},
			}
			want, _ = shellquote.Split(cmd)
			want = want[1:]
		}

		var existing [][]string
		exists := false
		if inspect {
			if existing, err = p.tripwireRules(tw.chain, ruleID); err != nil {
				return nil, queryError{err}
			}
			if want != nil {
				if exists, err = p.ruleExists(want); err != nil {
					return nil, queryError{err}
				}
			}
		}

		// Keep the rule matching the config, if present; every other rule
		// carrying this tripwire's ID is left over from an old port list
		keep := -1
		if exists {
			for i, rule := range existing {
				if equalArgs(rule, want) {
					keep = i
					break
				}
			}
			// iptables printed the rule differently from how it was written
			if keep == -1 && len(existing) == 1 {
				keep = 0
			}
			// Can't tell which copy is current, so remove them all and add it back
			if keep == -1 {
				exists = false
			}
		}

		for i, rule := range existing {
			if i == keep {
				continue
			}
			ports := argAfter(rule, "--dports")
			del := append([]string{"iptables", "-D"}, rule[1:]...)
			commands = append(commands, skills.SystemCommand{
				Command:     shellquote.Join(del...),
				Description: fmt.Sprintf("Remove outdated %s tripwire rule (ports: %s)", tw.label, ports),
				Metadata: map[string]string{
					"rule_id":   ruleID,
					"direction": tw.direction,
					"ports":     ports,
					"action":    "remove",
				},
			})
		}

		if add != nil && !exists {
			commands = append(commands, *add)
		}
	}

	return commands, nil
}

// tripwireRules returns the rules in chain whose LOG prefix is ruleID, as
// iptables -S prints them ("-A CHAIN ..."), split into arguments
func (p *PortTripwires) tripwireRules(chain, ruleID string) ([][]string, error) {
	out, err := p.run("-S", chain)
	if err != nil {
		return nil, err
	}

	var rules [][]string
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "-A ") {
			continue
		}
		args, err := shellquote.Split(line)
		if err != nil {
			continue
		}
		if argAfter(args, "--log-prefix") == ruleID+": " {
			rules = append(rules, args)
		}
	}
	return rules, nil
}

// ruleExists asks iptables whether rule (starting "-A CHAIN") is present
func (p *PortTripwires) ruleExists(rule []string) (bool, error) {
	_, err := p.run(append([]string{"-C"}, rule[1:]...)...)
	if err == nil {
		return true, nil
	}
	// iptables -C exits 1 when the rule doesn't exist; other codes are failures
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return false, nil
	}
	return false, err
}

func (p *PortTripwires) run(args ...string) ([]byte, error) {
	if p.iptables == nil {
		return runIptables(args...)
	}
	return p.iptables(args...)
}

// argAfter returns the argument following flag, or ""
func argAfter(args []string, flag string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

func equalArgs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Watch monitors system logs for port tripwire alerts
func (p *PortTripwires) Watch(ctx context.Context) (<-chan notifier.Alert, error) {
	alerts := make(chan notifier.Alert, 10)

	go func() {
		defer close(alerts)
		// TODO: Implement log watching for the generated rule IDs
		// This will monitor /var/log/kern.log or journalctl for our rule identifiers
		<-ctx.Done()
	}()

	return alerts, nil
}

// extractPorts safely extracts port list from config
func extractPorts(cfg map[string]interface{}, key string) ([]int, error) {
	val, ok := cfg[key]
	if !ok {
		return []int{}, nil
	}

	// Handle []interface{} from YAML parsing
	if portsInterface, ok := val.([]interface{}); ok {
		ports := make([]int, 0, len(portsInterface))
		for _, p := range portsInterface {
			switch v := p.(type) {
			case int:
				ports = append(ports, v)
			case float64:
				ports = append(ports, int(v))
			case string:
				port, err := strconv.Atoi(v)
				if err != nil {
					return nil, fmt.Errorf("invalid port value: %s", v)
				}
				ports = append(ports, port)
			default:
				return nil, fmt.Errorf("unexpected port type: %T", p)
			}
			if port := ports[len(ports)-1]; port < 1 || port > 65535 {
				return nil, fmt.Errorf("port %d out of range 1-65535", port)
			}
		}
		// iptables' multiport match takes at most 15 ports
		if len(ports) > 15 {
			return nil, fmt.Errorf("%s lists %d ports, iptables multiport allows at most 15", key, len(ports))
		}
		return ports, nil
	}

	return nil, fmt.Errorf("invalid port list format for %s", key)
}
