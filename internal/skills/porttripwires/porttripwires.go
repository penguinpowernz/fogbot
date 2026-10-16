package porttripwires

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kballard/go-shellquote"

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

	// cooldown is how long a tripwire stays quiet after alerting for the same
	// remote address and port
	cooldown time.Duration

	// kmsgPath is the kernel log device the LOG rules write to
	kmsgPath string
}

// New creates a new PortTripwires skill from config
// NewDefault creates a PortTripwires for daemon registration.
// Configure() will be called later with the actual YAML config.
func NewDefault() *PortTripwires {
	return &PortTripwires{
		id:       510,
		name:     "port-tripwires",
		config:   map[string]interface{}{},
		cooldown: defaultCooldown,
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
		cooldown:        defaultCooldown,
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
	p.cooldown = defaultCooldown
	if s, ok := cfg["alert_cooldown"].(string); ok {
		d, err := time.ParseDuration(s)
		if err != nil || d < 0 {
			return fmt.Errorf("invalid alert_cooldown %q", s)
		}
		p.cooldown = d
	}
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

// chainRef names a chain in an iptables table
type chainRef struct {
	table string
	chain string
}

func (c chainRef) String() string { return c.table + " " + c.chain }

// tripwire describes the LOG rule for one traffic direction.
//
// The rules live in the raw table. Firewall managers such as ufw own the
// filter table: ufw puts its chains at the head of INPUT, and they drop
// 137-139 and 445 and accept allowed ports before a rule appended to INPUT is
// ever reached, which blinded the tripwire to the very ports it watches. When
// ufw manages the built-in chains it also flushes the filter, mangle and nat
// tables on reload. It never touches raw, which every packet passes through
// before filter. A LOG rule there sees each connection attempt whatever ufw
// decides about it, and changes nothing about that decision.
type tripwire struct {
	direction string   // rule ID suffix
	chain     chainRef // where the rule goes
	legacy    chainRef // where earlier versions put it; such rules are removed
	configKey string
	label     string
	match     string // matches ahead of the port list
	logUID    bool   // log the UID of the local socket owner
}

var tripwires = []tripwire{
	{
		direction: "in",
		chain:     chainRef{"raw", "PREROUTING"},
		legacy:    chainRef{"filter", "INPUT"},
		configKey: "watch_inbound",
		label:     "inbound",
		// Only traffic to this machine: not loopback (a local client talking to
		// a local dev server), and not traffic routed through to VMs or containers
		match: "! -i lo -p tcp -m addrtype --dst-type LOCAL",
	},
	{
		direction: "out",
		chain:     chainRef{"raw", "OUTPUT"},
		legacy:    chainRef{"filter", "OUTPUT"},
		configKey: "watch_outbound",
		label:     "outbound",
		match:     "! -o lo -p tcp",
		// Outbound packets come from a local socket, so the kernel can say whose
		logUID: true,
	},
}

// ruleMatch narrows each LOG rule to new TCP connections: only the SYN that
// opens one is logged, not every packet of it, so an established C2 session
// doesn't flood the kernel log. The limit match caps logging at a burst of 20
// then one a second, enough for a scan of every watched port. Rules are
// written the way iptables -S prints them (--syn is shown as these
// --tcp-flags), so they can be matched exactly against the live ruleset.
const ruleMatch = "-m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m limit --limit 1/sec --limit-burst 20"

// ruleCommand returns the iptables command that adds tw's LOG rule for ports
func (tw tripwire) ruleCommand(ports, ruleID string) string {
	cmd := fmt.Sprintf("iptables -t %s -A %s %s -m multiport --dports %s %s -j LOG --log-prefix '%s: '",
		tw.chain.table, tw.chain.chain, tw.match, ports, ruleMatch, ruleID)
	if tw.logUID {
		cmd += " --log-uid"
	}
	return cmd
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
	ufw := inspect && p.ufwActive()

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
			cmd := tw.ruleCommand(portList, ruleID)
			desc := fmt.Sprintf("Log new %s TCP connections on ports: %s", tw.label, portList)
			if ufw {
				desc += " (ufw is active: this goes in the raw table, which ufw doesn't manage, so ufw's rules and their order are untouched)"
			}
			add = &skills.SystemCommand{
				Command:     cmd,
				Description: desc,
				Metadata: map[string]string{
					"rule_id":   ruleID,
					"direction": tw.direction,
					"ports":     portList,
				},
			}
			want, _ = shellquote.Split(cmd)
			want = want[3:] // drop "iptables -t <table>"
		}

		var existing, legacy [][]string
		exists := false
		if inspect {
			if existing, err = p.tripwireRules(tw.chain, ruleID); err != nil {
				return nil, queryError{err}
			}
			if legacy, err = p.tripwireRules(tw.legacy, ruleID); err != nil {
				return nil, queryError{err}
			}
			if want != nil {
				if exists, err = p.ruleExists(tw.chain.table, want); err != nil {
					return nil, queryError{err}
				}
			}
		}

		// Rules where earlier versions put them are always removed: behind
		// ufw's chains they miss traffic, and the raw rule replaces them
		for _, rule := range legacy {
			commands = append(commands, p.removeCommand(tw, tw.legacy, rule,
				fmt.Sprintf("Remove %s tripwire rule from its old place in %s (ports: %s)", tw.label, tw.legacy, argAfter(rule, "--dports"))))
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
			commands = append(commands, p.removeCommand(tw, tw.chain, rule,
				fmt.Sprintf("Remove outdated %s tripwire rule (ports: %s)", tw.label, argAfter(rule, "--dports"))))
		}

		if add != nil && !exists {
			commands = append(commands, *add)
		}
	}

	return commands, nil
}

// removeCommand returns the command deleting rule (as iptables -S printed it)
// from ref
func (p *PortTripwires) removeCommand(tw tripwire, ref chainRef, rule []string, desc string) skills.SystemCommand {
	ports := argAfter(rule, "--dports")
	del := append([]string{"iptables", "-t", ref.table, "-D"}, rule[1:]...)
	return skills.SystemCommand{
		Command:     joinArgs(del),
		Description: desc,
		Metadata: map[string]string{
			"rule_id":   p.generateRuleID(tw.direction),
			"direction": tw.direction,
			"ports":     ports,
			"action":    "remove",
		},
	}
}

// plainArg matches arguments that need no quoting for shellquote.Split
var plainArg = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./!-]+$`)

// joinArgs joins args into a command that shellquote.Split turns back into
// args, quoting only where needed so the approval prompt shows "! -i lo"
// rather than shellquote.Join's "\! -i lo"
func joinArgs(args []string) string {
	words := make([]string, len(args))
	for i, a := range args {
		if plainArg.MatchString(a) {
			words[i] = a
		} else {
			words[i] = shellquote.Join(a)
		}
	}
	return strings.Join(words, " ")
}

// ufwActive reports whether ufw's rules are loaded. ufw.conf can say
// ENABLED=yes while ufw isn't running, so the live ruleset is checked for the
// chains ufw creates.
func (p *PortTripwires) ufwActive() bool {
	out, err := p.run("-t", "filter", "-S")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if line == "-N ufw-before-input" {
			return true
		}
	}
	return false
}

// tripwireRules returns the rules in ref whose LOG prefix is ruleID, as
// iptables -S prints them ("-A CHAIN ..."), split into arguments
func (p *PortTripwires) tripwireRules(ref chainRef, ruleID string) ([][]string, error) {
	out, err := p.run("-t", ref.table, "-S", ref.chain)
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

// ruleExists asks iptables whether rule (starting "-A CHAIN") is present in table
func (p *PortTripwires) ruleExists(table string, rule []string) (bool, error) {
	_, err := p.run(append([]string{"-t", table, "-C"}, rule[1:]...)...)
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
