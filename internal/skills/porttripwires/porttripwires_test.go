package porttripwires

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/kballard/go-shellquote"

	"github.com/penguinpowernz/fogbot/internal/skills"
)

// fakeIptables keeps a ruleset in memory and answers -S, -C, -A and -D like
// iptables does, printing rules the way iptables -S does
type fakeIptables struct {
	rules  map[string][][]string // "table chain" -> rule args after "-A CHAIN"
	chains []string              // user-defined filter chains, e.g. ufw's
	v6     *fakeIptables         // the ip6tables ruleset
}

func newFake() *fakeIptables {
	return &fakeIptables{rules: map[string][][]string{}, v6: &fakeIptables{rules: map[string][][]string{}}}
}

// withUFW makes the fake look like a host where ufw's rules are loaded
func (f *fakeIptables) withUFW() *fakeIptables {
	f.chains = []string{"ufw-before-logging-input", "ufw-before-input", "ufw-after-input"}
	for _, c := range f.chains {
		f.rules["filter INPUT"] = append(f.rules["filter INPUT"], []string{"-j", c})
	}
	return f
}

// run answers for iptables from f and for ip6tables from f.v6
func (f *fakeIptables) run(tool string, args ...string) ([]byte, error) {
	switch tool {
	case "iptables":
		return f.runFamily(args...)
	case "ip6tables":
		return f.v6.runFamily(args...)
	}
	return nil, fmt.Errorf("unexpected tool %s", tool)
}

func (f *fakeIptables) runFamily(args ...string) ([]byte, error) {
	table := "filter"
	if len(args) >= 2 && args[0] == "-t" {
		table, args = args[1], args[2:]
	}
	if len(args) == 1 && args[0] == "-S" && table == "filter" {
		var b strings.Builder
		for _, c := range f.chains {
			fmt.Fprintf(&b, "-N %s\n", c)
		}
		return []byte(b.String()), nil
	}
	if len(args) < 2 {
		return nil, fmt.Errorf("bad args %v", args)
	}
	op, chain, spec := args[0], args[1], args[2:]
	key := table + " " + chain
	switch op {
	case "-S":
		var b strings.Builder
		fmt.Fprintf(&b, "-P %s ACCEPT\n", chain)
		for _, r := range f.rules[key] {
			words := []string{"-A", chain}
			for _, w := range r {
				if strings.Contains(w, " ") {
					w = strconv.Quote(w)
				}
				words = append(words, w)
			}
			b.WriteString(strings.Join(words, " ") + "\n")
		}
		return []byte(b.String()), nil
	case "-A":
		f.rules[key] = append(f.rules[key], spec)
		return nil, nil
	case "-C", "-D":
		for i, r := range f.rules[key] {
			if equalArgs(r, spec) {
				if op == "-D" {
					f.rules[key] = append(f.rules[key][:i:i], f.rules[key][i+1:]...)
				}
				return nil, nil
			}
		}
		return nil, exec.Command("false").Run() // exit status 1, like iptables
	}
	return nil, fmt.Errorf("unsupported op %s", op)
}

// chainOf maps a direction's built-in chain name to where its rule now lives
var chainOf = map[string]string{"INPUT": "raw PREROUTING", "OUTPUT": "raw OUTPUT"}

// add installs a tripwire rule as the current version writes it
func (f *fakeIptables) add(chain, ports, prefix string) {
	args, _ := shellquote.Split(rule("-A", chain, ports, prefix))
	f.rules[chainOf[chain]] = append(f.rules[chainOf[chain]], args[5:])
}

// addLegacy installs a rule as versions before the raw table wrote it: in the
// filter table, behind any ufw chains, logging every packet
func (f *fakeIptables) addLegacy(chain, ports, prefix string) {
	f.rules["filter "+chain] = append(f.rules["filter "+chain], []string{"-p", "tcp", "-m", "multiport", "--dports", ports, "-j", "LOG", "--log-prefix", prefix})
}

// legacyRule returns the command for a rule addLegacy installed
func legacyRule(op, chain, ports, prefix string) string {
	return fmt.Sprintf("iptables -t filter %s %s -p tcp -m multiport --dports %s -j LOG --log-prefix '%s'", op, chain, ports, prefix)
}

// rule returns the iptables command for a tripwire rule in the given
// direction's chain (INPUT or OUTPUT), as iptables -S prints it
func rule(op, chain, ports, prefix string) string {
	return ruleFor("iptables", op, chain, ports, prefix)
}

// ruleFor is rule for tool (iptables or ip6tables)
func ruleFor(tool, op, chain, ports, prefix string) string {
	match := "PREROUTING ! -i lo -p tcp -m addrtype --dst-type LOCAL"
	if chain == "OUTPUT" {
		match = "OUTPUT ! -o lo -p tcp"
	}
	cmd := fmt.Sprintf("%s -t raw %s %s -m multiport --dports %s -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m limit --limit 1/sec --limit-burst 20 -j LOG --log-prefix '%s'", tool, op, match, ports, prefix)
	if chain == "OUTPUT" {
		cmd += " --log-uid"
	}
	return cmd
}

// apply runs commands the way the enabler does
func (f *fakeIptables) apply(t *testing.T, p *PortTripwires) {
	t.Helper()
	cmds, err := p.DeduceCommands(p.Config())
	if err != nil {
		t.Fatalf("DeduceCommands: %v", err)
	}
	for _, c := range cmds {
		args, err := shellquote.Split(c.Command)
		if err != nil || (args[0] != "iptables" && args[0] != "ip6tables") {
			t.Fatalf("bad command %q: %v", c.Command, err)
		}
		if _, err := f.run(args[0], args[1:]...); err != nil {
			t.Fatalf("command %q failed: %v", c.Command, err)
		}
	}
}

// newSkill returns the skill on an IPv4-only host whose rules are in f
func newSkill(f *fakeIptables, in, out []interface{}) *PortTripwires {
	p := NewDefault()
	p.iptables = f.run
	p.ipv6 = func() bool { return false }
	cfg := map[string]interface{}{}
	if in != nil {
		cfg["watch_inbound"] = in
	}
	if out != nil {
		cfg["watch_outbound"] = out
	}
	p.Configure(cfg)
	return p
}

func commands(t *testing.T, p *PortTripwires) []string {
	t.Helper()
	cmds, err := p.DeduceCommands(p.Config())
	if err != nil {
		t.Fatalf("DeduceCommands: %v", err)
	}
	var out []string
	for _, c := range cmds {
		out = append(out, c.Command)
	}
	return out
}

func configured(t *testing.T, p *PortTripwires) bool {
	t.Helper()
	ok, err := p.CheckSystemState()
	if err != nil {
		t.Fatalf("CheckSystemState: %v", err)
	}
	return ok
}

func TestFreshSystemAddsBothRules(t *testing.T) {
	f := newFake()
	p := newSkill(f, []interface{}{135, 445}, []interface{}{4444})

	if configured(t, p) {
		t.Fatal("empty ruleset reported as configured")
	}
	want := []string{
		rule("-A", "INPUT", "135,445", "fw-510-in: "),
		rule("-A", "OUTPUT", "4444", "fw-510-out: "),
	}
	if got := commands(t, p); !equalArgs(got, want) {
		t.Fatalf("commands:\n got %q\nwant %q", got, want)
	}

	f.apply(t, p)
	if !configured(t, p) {
		t.Fatal("not configured after applying commands")
	}
	if got := commands(t, p); len(got) != 0 {
		t.Fatalf("expected no commands once configured, got %q", got)
	}
}

// The bug: a changed port list still had a rule with the same ID, so it was
// reported as configured and the new ports were never applied
func TestChangedPortListReplacesRule(t *testing.T) {
	f := newFake()
	f.add("INPUT", "135", "fw-510-in: ")
	f.add("OUTPUT", "4444", "fw-510-out: ")
	p := newSkill(f, []interface{}{135, 445}, []interface{}{4444})

	if configured(t, p) {
		t.Fatal("changed inbound port list reported as configured")
	}
	want := []string{
		rule("-D", "INPUT", "135", "fw-510-in: "),
		rule("-A", "INPUT", "135,445", "fw-510-in: "),
	}
	if got := commands(t, p); !equalArgs(got, want) {
		t.Fatalf("commands:\n got %q\nwant %q", got, want)
	}

	f.apply(t, p)
	if !configured(t, p) {
		t.Fatal("not configured after applying commands")
	}
	if n := len(f.rules["raw PREROUTING"]); n != 1 {
		t.Fatalf("expected 1 inbound rule, got %d: %v", n, f.rules["raw PREROUTING"])
	}
}

// Rules earlier versions put in the filter table are moved to the raw table
func TestLegacyRuleIsReplaced(t *testing.T) {
	f := newFake()
	f.addLegacy("INPUT", "135", "fw-510-in: ")
	f.addLegacy("OUTPUT", "4444", "fw-510-out: ")
	p := newSkill(f, []interface{}{135}, []interface{}{4444})

	if configured(t, p) {
		t.Fatal("legacy rules reported as configured")
	}
	want := []string{
		legacyRule("-D", "INPUT", "135", "fw-510-in: "),
		rule("-A", "INPUT", "135", "fw-510-in: "),
		legacyRule("-D", "OUTPUT", "4444", "fw-510-out: "),
		rule("-A", "OUTPUT", "4444", "fw-510-out: "),
	}
	if got := commands(t, p); !equalArgs(got, want) {
		t.Fatalf("commands:\n got %q\nwant %q", got, want)
	}
	f.apply(t, p)
	if !configured(t, p) || len(f.rules["raw PREROUTING"]) != 1 || len(f.rules["raw OUTPUT"]) != 1 ||
		len(f.rules["filter INPUT"]) != 0 || len(f.rules["filter OUTPUT"]) != 0 {
		t.Fatalf("expected one raw rule per direction and none in filter, got %v", f.rules)
	}
}

func TestRemovedDirectionDeletesRule(t *testing.T) {
	f := newFake()
	f.add("INPUT", "135", "fw-510-in: ")
	f.add("OUTPUT", "4444", "fw-510-out: ")
	p := newSkill(f, []interface{}{135}, nil)

	if configured(t, p) {
		t.Fatal("leftover outbound rule reported as configured")
	}
	f.apply(t, p)
	if len(f.rules["raw OUTPUT"]) != 0 || len(f.rules["raw PREROUTING"]) != 1 {
		t.Fatalf("unexpected rules after apply: %v", f.rules)
	}
}

func TestDuplicateRuleIsRemovedNotReadded(t *testing.T) {
	f := newFake()
	f.add("INPUT", "135", "fw-510-in: ")
	f.add("INPUT", "135", "fw-510-in: ")
	p := newSkill(f, []interface{}{135}, nil)

	want := []string{rule("-D", "INPUT", "135", "fw-510-in: ")}
	if got := commands(t, p); !equalArgs(got, want) {
		t.Fatalf("commands:\n got %q\nwant %q", got, want)
	}
	f.apply(t, p)
	if !configured(t, p) || len(f.rules["raw PREROUTING"]) != 1 {
		t.Fatalf("expected exactly one rule, got %v", f.rules["raw PREROUTING"])
	}
}

func TestOtherRulesAreLeftAlone(t *testing.T) {
	f := newFake()
	f.add("INPUT", "22", "fw-510-inbound: ")
	f.add("INPUT", "80", "other: ")
	f.rules["raw PREROUTING"] = append(f.rules["raw PREROUTING"], []string{"-p", "tcp", "--dport", "22", "-j", "CT", "--notrack"})
	f.addLegacy("INPUT", "80", "other: ")
	p := newSkill(f, []interface{}{135}, nil)

	f.apply(t, p)
	if n := len(f.rules["raw PREROUTING"]); n != 4 {
		t.Fatalf("expected the 3 unrelated rules plus ours, got %d: %v", n, f.rules["raw PREROUTING"])
	}
	if n := len(f.rules["filter INPUT"]); n != 1 {
		t.Fatalf("an unrelated filter rule was touched: %v", f.rules["filter INPUT"])
	}
}

// With ufw active, the rules go in the raw table and ufw's own rules in the
// filter table are left exactly as they were
func TestUFWRulesAreLeftAlone(t *testing.T) {
	f := newFake().withUFW()
	ufwRules := fmt.Sprint(f.rules["filter INPUT"])
	p := newSkill(f, []interface{}{445}, []interface{}{4444})

	if !p.ufwActive() {
		t.Fatal("ufw not detected")
	}
	cmds, err := p.DeduceCommands(p.Config())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cmds {
		if !strings.HasPrefix(c.Command, "iptables -t raw -A ") {
			t.Errorf("command outside the raw table: %s", c.Command)
		}
		if !strings.Contains(c.Description, "ufw is active") {
			t.Errorf("description doesn't mention ufw: %s", c.Description)
		}
	}

	f.apply(t, p)
	if got := fmt.Sprint(f.rules["filter INPUT"]); got != ufwRules {
		t.Fatalf("ufw's INPUT rules changed:\n got %s\nwant %s", got, ufwRules)
	}
	if !configured(t, p) {
		t.Fatal("not configured after applying commands")
	}
}

func TestUFWNotDetectedWithoutItsChains(t *testing.T) {
	p := newSkill(newFake(), []interface{}{445}, nil)
	if p.ufwActive() {
		t.Fatal("ufw detected on a host without its chains")
	}
	cmds, _ := p.DeduceCommands(p.Config())
	if len(cmds) != 1 || strings.Contains(cmds[0].Description, "ufw") {
		t.Fatalf("unexpected commands: %+v", cmds)
	}
}

func TestQueryFailure(t *testing.T) {
	p := NewDefault()
	p.iptables = func(string, ...string) ([]byte, error) { return nil, fmt.Errorf("permission denied") }
	p.ipv6 = func() bool { return false }
	p.Configure(map[string]interface{}{"watch_inbound": []interface{}{135}})

	if _, err := p.CheckSystemState(); err == nil {
		t.Error("CheckSystemState should fail when iptables can't be read")
	}
	// A dry run without root still shows what would be added
	cmds, err := p.DeduceCommands(p.Config())
	if err != nil || len(cmds) != 1 {
		t.Fatalf("expected the add command despite the query failure, got %v, %v", cmds, err)
	}
}

func TestInvalidPorts(t *testing.T) {
	for _, ports := range [][]interface{}{{0}, {70000}, {"x"}, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}} {
		p := newSkill(newFake(), ports, nil)
		if _, err := p.DeduceCommands(p.Config()); err == nil {
			t.Errorf("expected error for ports %v", ports)
		}
	}
}

func TestJoinArgsRoundTrips(t *testing.T) {
	args := []string{"iptables", "-t", "raw", "-D", "PREROUTING", "!", "-i", "lo", "--log-prefix", "fw-510-in: ", "it's", "$(id)"}
	got, err := shellquote.Split(joinArgs(args))
	if err != nil || !equalArgs(got, args) {
		t.Fatalf("round trip: got %q (%v), want %q", got, err, args)
	}
}

// The bug: only iptables rules were written, so a connection over IPv6 (a
// link-local fe80:: address is up on every LAN interface) reached the watched
// ports without tripping anything
func TestIPv6HostGetsIp6tablesRules(t *testing.T) {
	f := newFake()
	p := newSkill(f, []interface{}{445}, []interface{}{4444})
	p.ipv6 = func() bool { return true }

	want := []string{
		rule("-A", "INPUT", "445", "fw-510-in: "),
		rule("-A", "OUTPUT", "4444", "fw-510-out: "),
		ruleFor("ip6tables", "-A", "INPUT", "445", "fw-510-in: "),
		ruleFor("ip6tables", "-A", "OUTPUT", "4444", "fw-510-out: "),
	}
	if got := commands(t, p); !equalArgs(got, want) {
		t.Fatalf("commands:\n got %q\nwant %q", got, want)
	}

	f.apply(t, p)
	if !configured(t, p) {
		t.Fatal("not configured after applying commands")
	}
	if len(f.v6.rules["raw PREROUTING"]) != 1 || len(f.v6.rules["raw OUTPUT"]) != 1 {
		t.Fatalf("expected one ip6tables rule per direction, got %v", f.v6.rules)
	}
}

// A host upgraded from an IPv4-only version only needs the ip6tables rules
// added, and an IPv4 rule that went missing is reported
func TestMissingIp6tablesRulesAreAdded(t *testing.T) {
	f := newFake()
	f.add("INPUT", "445", "fw-510-in: ")
	f.add("OUTPUT", "4444", "fw-510-out: ")
	p := newSkill(f, []interface{}{445}, []interface{}{4444})
	if !configured(t, p) {
		t.Fatal("IPv4-only host with both rules should be configured")
	}

	p.ipv6 = func() bool { return true }
	if configured(t, p) {
		t.Fatal("missing ip6tables rules reported as configured")
	}
	want := []string{
		ruleFor("ip6tables", "-A", "INPUT", "445", "fw-510-in: "),
		ruleFor("ip6tables", "-A", "OUTPUT", "4444", "fw-510-out: "),
	}
	if got := commands(t, p); !equalArgs(got, want) {
		t.Fatalf("commands:\n got %q\nwant %q", got, want)
	}
	f.apply(t, p)

	f.rules["raw PREROUTING"] = nil
	if configured(t, p) {
		t.Fatal("missing iptables rule reported as configured")
	}
}

// runAll runs commands against f the way the enabler does
func (f *fakeIptables) runAll(t *testing.T, cmds []skills.SystemCommand) {
	t.Helper()
	for _, c := range cmds {
		args, err := shellquote.Split(c.Command)
		if err != nil {
			t.Fatalf("bad command %q: %v", c.Command, err)
		}
		if _, err := f.run(args[0], args[1:]...); err != nil {
			t.Fatalf("command %q failed: %v", c.Command, err)
		}
	}
}

// Disabling the skill must remove its rules: left in place, a later enable
// found them, recorded no approval, and startup repair couldn't restore them
func TestTeardownRemovesEveryTripwireRule(t *testing.T) {
	f := newFake()
	p := newSkill(f, []interface{}{445}, []interface{}{4444})
	p.ipv6 = func() bool { return true }
	f.apply(t, p)
	// A rule from an older port list and one where old versions put it
	f.add("INPUT", "139", "fw-510-in: ")
	f.addLegacy("INPUT", "135", "fw-510-in: ")
	f.rules["raw PREROUTING"] = append(f.rules["raw PREROUTING"], []string{"-j", "ACCEPT"}) // not ours

	cmds, err := p.TeardownCommands()
	if err != nil {
		t.Fatal(err)
	}
	f.runAll(t, cmds)

	for _, ruleset := range []*fakeIptables{f, f.v6} {
		for chain, rules := range ruleset.rules {
			for _, r := range rules {
				if argAfter(r, "--log-prefix") != "" {
					t.Fatalf("tripwire rule left in %s: %v", chain, r)
				}
			}
		}
	}
	if len(f.rules["raw PREROUTING"]) != 1 {
		t.Fatalf("other rules must be left alone, got %v", f.rules["raw PREROUTING"])
	}
}

// Startup repair after a reboot needs the add commands approved, which
// DeduceCommands doesn't return while the rules are in place
func TestSetupCommandsListAddsWhenConfigured(t *testing.T) {
	f := newFake()
	p := newSkill(f, []interface{}{445}, []interface{}{4444})
	f.apply(t, p)

	setup, err := p.SetupCommands(p.Config())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		rule("-A", "INPUT", "445", "fw-510-in: "),
		rule("-A", "OUTPUT", "4444", "fw-510-out: "),
	}
	var got []string
	for _, c := range setup {
		got = append(got, c.Command)
	}
	if !equalArgs(got, want) {
		t.Fatalf("setup commands:\n got %q\nwant %q", got, want)
	}

	// They are what repair deduces once the rules are gone
	f.rules = map[string][][]string{}
	if deduced := commands(t, p); !equalArgs(deduced, want) {
		t.Fatalf("repair would deduce %q, not the approved %q", deduced, want)
	}
}
