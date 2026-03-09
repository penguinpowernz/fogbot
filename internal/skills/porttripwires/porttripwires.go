package porttripwires

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

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
}

// New creates a new PortTripwires skill from config
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

func (p *PortTripwires) Configure(cfg map[string]interface{}) error {
	p.config = cfg
	return nil
}

// generateRuleID creates an identifier based on skill ID and direction
func (p *PortTripwires) generateRuleID(direction string) string {
	// Use fw-<skillID>-<direction> format (e.g., fw-510-in, fw-510-out)
	return fmt.Sprintf("fw-%d-%s", p.id, direction)
}

// DeduceCommands generates iptables commands from the declarative config
func (p *PortTripwires) DeduceCommands(cfg map[string]interface{}) ([]skills.SystemCommand, error) {
	commands := []skills.SystemCommand{}

	// Extract port lists from config
	inboundPorts, err := extractPorts(cfg, "watch_inbound")
	if err != nil {
		return nil, fmt.Errorf("invalid watch_inbound config: %w", err)
	}

	outboundPorts, err := extractPorts(cfg, "watch_outbound")
	if err != nil {
		return nil, fmt.Errorf("invalid watch_outbound config: %w", err)
	}

	// Generate non-obvious rule identifiers
	inboundID := p.generateRuleID("in")
	outboundID := p.generateRuleID("out")

	// Build inbound monitoring command
	if len(inboundPorts) > 0 {
		portList := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(inboundPorts)), ","), "[]")
		cmd := fmt.Sprintf(
			"iptables -A INPUT -p tcp -m multiport --dports %s -j LOG --log-prefix '%s: '",
			portList, inboundID,
		)
		commands = append(commands, skills.SystemCommand{
			Command:     cmd,
			Description: fmt.Sprintf("Monitor inbound traffic on ports: %s", portList),
			Metadata: map[string]string{
				"rule_id":   inboundID,
				"direction": "in",
				"ports":     portList,
			},
		})
	}

	// Build outbound monitoring command
	if len(outboundPorts) > 0 {
		portList := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(outboundPorts)), ","), "[]")
		cmd := fmt.Sprintf(
			"iptables -A OUTPUT -p tcp -m multiport --dports %s -j LOG --log-prefix '%s: '",
			portList, outboundID,
		)
		commands = append(commands, skills.SystemCommand{
			Command:     cmd,
			Description: fmt.Sprintf("Monitor outbound traffic on ports: %s", portList),
			Metadata: map[string]string{
				"rule_id":   outboundID,
				"direction": "out",
				"ports":     portList,
			},
		})
	}

	return commands, nil
}

// CheckSystemState verifies if iptables rules are already configured
func (p *PortTripwires) CheckSystemState() (bool, error) {
	// Get current iptables rules
	cmd := exec.Command("iptables", "-L", "-n", "-v", "--line-numbers")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to check iptables: %w", err)
	}

	rulesOutput := string(output)

	// Generate the rule IDs we expect to find
	inboundID := p.generateRuleID("in")
	outboundID := p.generateRuleID("out")

	// Check if both rule IDs exist in the output
	hasInbound := strings.Contains(rulesOutput, inboundID)
	hasOutbound := strings.Contains(rulesOutput, outboundID)

	// Determine which rules should exist based on config
	inboundPorts, _ := extractPorts(p.config, "watch_inbound")
	outboundPorts, _ := extractPorts(p.config, "watch_outbound")

	expectedInbound := len(inboundPorts) > 0
	expectedOutbound := len(outboundPorts) > 0

	// System is properly configured if all expected rules are present
	if expectedInbound && !hasInbound {
		return false, nil
	}
	if expectedOutbound && !hasOutbound {
		return false, nil
	}

	return true, nil
}

// Watch monitors system logs for port tripwire alerts
func (p *PortTripwires) Watch(ctx context.Context) (<-chan notifier.Alert, error) {
	alerts := make(chan notifier.Alert)

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
		}
		return ports, nil
	}

	return nil, fmt.Errorf("invalid port list format for %s", key)
}
