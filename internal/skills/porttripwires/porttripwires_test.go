package porttripwires

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/kballard/go-shellquote"
)

// fakeIptables keeps a ruleset in memory and answers -S, -C, -A and -D like
// iptables does, printing rules the way iptables -S does
type fakeIptables struct {
	rules map[string][][]string // chain -> rule args after "-A CHAIN"
}

func newFake() *fakeIptables {
	return &fakeIptables{rules: map[string][][]string{}}
}

func (f *fakeIptables) run(args ...string) ([]byte, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("bad args %v", args)
	}
	op, chain, spec := args[0], args[1], args[2:]
	switch op {
	case "-S":
		var b strings.Builder
		fmt.Fprintf(&b, "-P %s ACCEPT\n", chain)
		for _, r := range f.rules[chain] {
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
		f.rules[chain] = append(f.rules[chain], spec)
		return nil, nil
	case "-C", "-D":
		for i, r := range f.rules[chain] {
			if equalArgs(r, spec) {
				if op == "-D" {
					f.rules[chain] = append(f.rules[chain][:i:i], f.rules[chain][i+1:]...)
				}
				return nil, nil
			}
		}
		return nil, exec.Command("false").Run() // exit status 1, like iptables
	}
	return nil, fmt.Errorf("unsupported op %s", op)
}

// add installs a tripwire rule as the current version writes it
func (f *fakeIptables) add(chain, ports, prefix string) {
	args, _ := shellquote.Split(rule("-A", chain, ports, prefix))
	f.rules[chain] = append(f.rules[chain], args[3:])
}

// addLegacy installs a rule as versions before SYN-only logging wrote it
func (f *fakeIptables) addLegacy(chain, ports, prefix string) {
	f.rules[chain] = append(f.rules[chain], []string{"-p", "tcp", "-m", "multiport", "--dports", ports, "-j", "LOG", "--log-prefix", prefix})
}

// rule returns the iptables command for a tripwire rule, as iptables -S prints it
func rule(op, chain, ports, prefix string) string {
	cmd := fmt.Sprintf("iptables %s %s -p tcp -m multiport --dports %s -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m limit --limit 1/sec --limit-burst 20 -j LOG --log-prefix '%s'", op, chain, ports, prefix)
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
		if err != nil || args[0] != "iptables" {
			t.Fatalf("bad command %q: %v", c.Command, err)
		}
		if _, err := f.run(args[1:]...); err != nil {
			t.Fatalf("command %q failed: %v", c.Command, err)
		}
	}
}

func newSkill(f *fakeIptables, in, out []interface{}) *PortTripwires {
	p := NewDefault()
	p.iptables = f.run
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
	if n := len(f.rules["INPUT"]); n != 1 {
		t.Fatalf("expected 1 INPUT rule, got %d: %v", n, f.rules["INPUT"])
	}
}

// Rules from before SYN-only logging logged every packet; they are replaced
func TestLegacyRuleIsReplaced(t *testing.T) {
	f := newFake()
	f.addLegacy("INPUT", "135", "fw-510-in: ")
	f.addLegacy("OUTPUT", "4444", "fw-510-out: ")
	p := newSkill(f, []interface{}{135}, []interface{}{4444})

	if configured(t, p) {
		t.Fatal("legacy rules reported as configured")
	}
	want := []string{
		"iptables -D INPUT -p tcp -m multiport --dports 135 -j LOG --log-prefix 'fw-510-in: '",
		rule("-A", "INPUT", "135", "fw-510-in: "),
		"iptables -D OUTPUT -p tcp -m multiport --dports 4444 -j LOG --log-prefix 'fw-510-out: '",
		rule("-A", "OUTPUT", "4444", "fw-510-out: "),
	}
	if got := commands(t, p); !equalArgs(got, want) {
		t.Fatalf("commands:\n got %q\nwant %q", got, want)
	}
	f.apply(t, p)
	if !configured(t, p) || len(f.rules["INPUT"]) != 1 || len(f.rules["OUTPUT"]) != 1 {
		t.Fatalf("expected one current rule per chain, got %v", f.rules)
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
	if len(f.rules["OUTPUT"]) != 0 || len(f.rules["INPUT"]) != 1 {
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
	if !configured(t, p) || len(f.rules["INPUT"]) != 1 {
		t.Fatalf("expected exactly one rule, got %v", f.rules["INPUT"])
	}
}

func TestOtherRulesAreLeftAlone(t *testing.T) {
	f := newFake()
	f.add("INPUT", "22", "fw-510-inbound: ")
	f.add("INPUT", "80", "other: ")
	f.rules["INPUT"] = append(f.rules["INPUT"], []string{"-p", "tcp", "--dport", "22", "-j", "ACCEPT"})
	p := newSkill(f, []interface{}{135}, nil)

	f.apply(t, p)
	if n := len(f.rules["INPUT"]); n != 4 {
		t.Fatalf("expected the 3 unrelated rules plus ours, got %d: %v", n, f.rules["INPUT"])
	}
}

func TestQueryFailure(t *testing.T) {
	p := NewDefault()
	p.iptables = func(args ...string) ([]byte, error) { return nil, fmt.Errorf("permission denied") }
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
