package netdiscover

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/penguinpowernz/fogbot/internal/baseline"
	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
	"golang.org/x/sys/unix"
)

func mustMAC(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

const gwMAC = "00:11:22:33:44:55"

// testWatcher returns a watcher on eth0, a network keyed by gwMAC, collecting
// alerts in a buffered channel
func testWatcher(t *testing.T) (*watcher, chan notifier.Alert, *baseline.Manager) {
	t.Helper()
	mgr := baseline.NewManager(t.TempDir())
	n := New(mgr)
	n.vendor = func(net.HardwareAddr) string { return "Acme" }
	n.reverseDNS = func(net.IP) string { return "box.lan" }
	alerts := make(chan notifier.Alert, 10)
	w := newWatcher(n, alerts)
	w.snap = snapshot{
		watched:  []string{"eth0"},
		networks: map[string]network{"eth0": {key: gwMAC, gatewayIP: "192.168.1.1"}},
		own:      map[string]bool{"02:00:00:00:00:01": true},
	}
	return w, alerts, mgr
}

func see(w *watcher, mac, ip string) {
	w.observe(sighting{iface: "eth0", mac: mustMAC(mac), ip: net.ParseIP(ip), source: "ARP"})
	w.flush()
}

func drain(ch chan notifier.Alert) []notifier.Alert {
	var out []notifier.Alert
	for {
		select {
		case a := <-ch:
			out = append(out, a)
		default:
			return out
		}
	}
}

func TestLearnsUnapprovedNetworkThenAlertsOnNewHost(t *testing.T) {
	w, alerts, mgr := testWatcher(t)

	see(w, gwMAC, "192.168.1.1")
	see(w, "aa:aa:aa:aa:aa:01", "192.168.1.10")

	got := drain(alerts)
	if len(got) != 1 || got[0].Severity != notifier.SeverityNominal {
		t.Fatalf("expected one pending-approval alert while learning, got %+v", got)
	}
	pending, _ := mgr.LoadPendingNet()
	if p := pending[gwMAC]; p == nil || len(p.Hosts) != 2 || p.Interface != "eth0" {
		t.Fatalf("expected both hosts pending, got %+v", pending)
	}

	if err := mgr.ApproveReviewedNet(pending, "test"); err != nil {
		t.Fatal(err)
	}
	if p, _ := mgr.LoadPendingNet(); len(p) != 0 {
		t.Errorf("approved hosts should leave the pending file, got %+v", p)
	}
	w.approved, _ = mgr.LoadNet()

	see(w, "aa:aa:aa:aa:aa:01", "192.168.1.11") // known, new IP
	see(w, "b4:bb:bb:bb:bb:02", "192.168.1.66")
	see(w, "b4:bb:bb:bb:bb:02", "192.168.1.66") // only once

	got = drain(alerts)
	if len(got) != 1 {
		t.Fatalf("expected one new-host alert, got %+v", got)
	}
	a := got[0]
	if a.Severity != notifier.SeverityContact || a.Metadata["mac"] != "b4:bb:bb:bb:bb:02" || a.Metadata["ip"] != "192.168.1.66" ||
		a.Metadata["vendor"] != "Acme" || a.Metadata["rdns"] != "box.lan" || a.Location != "eth0 (gateway 192.168.1.1)" {
		t.Errorf("unexpected alert %+v", a)
	}
	pending, _ = mgr.LoadPendingNet()
	if p := pending[gwMAC]; p == nil || len(p.Hosts) != 1 {
		t.Errorf("new host should be pending approval, got %+v", pending)
	}
}

func TestIgnoresOwnExcludedMulticastAndUnknownNetworks(t *testing.T) {
	w, alerts, mgr := testWatcher(t)
	mgr.ApproveReviewedNet(map[string]*baseline.NetPending{gwMAC: {Interface: "eth0", Hosts: map[string]baseline.NetHost{}}}, "test")
	w.approved, _ = mgr.LoadNet()
	w.excludeMACs = map[string]bool{"cc:cc:cc:cc:cc:cc": true}

	see(w, "02:00:00:00:00:01", "192.168.1.2") // own
	see(w, "CC:CC:CC:CC:CC:CC", "192.168.1.3") // excluded, case-insensitive
	see(w, "01:00:5e:00:00:fb", "224.0.0.251") // multicast
	see(w, "00:00:00:00:00:00", "192.168.1.4")
	w.observe(sighting{iface: "wlan0", mac: mustMAC("dd:dd:dd:dd:dd:dd")})

	if got := drain(alerts); len(got) != 0 {
		t.Fatalf("expected no alerts, got %+v", got)
	}
}

func TestReviewedOnlyApproval(t *testing.T) {
	mgr := baseline.NewManager(t.TempDir())
	host := func(mac string) baseline.NetHost { return baseline.NetHost{MAC: mac} }
	reviewed := map[string]*baseline.NetPending{gwMAC: {Interface: "eth0", Hosts: map[string]baseline.NetHost{"aa": host("aa")}}}
	// A host joined after the operator's review
	mgr.SavePendingNet(map[string]*baseline.NetPending{gwMAC: {Interface: "eth0", Hosts: map[string]baseline.NetHost{"aa": host("aa"), "bb": host("bb")}}})

	if err := mgr.ApproveReviewedNet(reviewed, "test"); err != nil {
		t.Fatal(err)
	}
	approved, _ := mgr.LoadNet()
	pending, _ := mgr.LoadPendingNet()
	if _, ok := approved[gwMAC].Hosts["bb"]; ok {
		t.Error("unreviewed host was approved")
	}
	if _, ok := pending[gwMAC].Hosts["bb"]; !ok || len(pending[gwMAC].Hosts) != 1 {
		t.Errorf("unreviewed host should stay pending, got %+v", pending[gwMAC])
	}
}

func TestBuildSnapshot(t *testing.T) {
	ifs := []net.Interface{
		{Index: 2, Name: "eth0", HardwareAddr: mustMAC("02:00:00:00:00:01")},
		{Index: 3, Name: "docker0", HardwareAddr: mustMAC("02:00:00:00:00:02")},
	}
	routes := []defaultRoute{{iface: "eth0", gateway: net.IPv4(192, 168, 1, 1).To4()}}
	neighs := []neighbour{
		{ifindex: 2, ip: net.IPv4(192, 168, 1, 1).To4(), mac: mustMAC(gwMAC)},
		{ifindex: 2, ip: net.IPv4(192, 168, 1, 9).To4(), mac: mustMAC("aa:aa:aa:aa:aa:09")},
		{ifindex: 3, ip: net.IPv4(172, 17, 0, 2).To4(), mac: mustMAC("02:42:ac:11:00:02")},
	}

	snap := buildSnapshot(nil, routes, ifs, neighs)
	if len(snap.watched) != 1 || snap.watched[0] != "eth0" {
		t.Fatalf("expected the default-route interface, got %v", snap.watched)
	}
	if nw := snap.networks["eth0"]; nw.key != gwMAC || nw.gatewayIP != "192.168.1.1" {
		t.Errorf("network keyed by gateway MAC expected, got %+v", nw)
	}
	if len(snap.seen) != 2 {
		t.Errorf("docker0 neighbours should be left out, got %+v", snap.seen)
	}
	if !snap.own["02:00:00:00:00:02"] {
		t.Error("own MACs should be recorded")
	}

	// Listed interface without a default route: one baseline per interface
	snap = buildSnapshot([]string{"docker0"}, routes, ifs, neighs)
	if snap.networks["docker0"].key != "if:docker0" || len(snap.seen) != 1 {
		t.Errorf("got %+v", snap)
	}

	// Gateway not resolved yet: network unknown
	snap = buildSnapshot(nil, routes, ifs, neighs[1:])
	if _, ok := snap.networks["eth0"]; ok || len(snap.seen) != 0 {
		t.Errorf("expected no network before the gateway resolves, got %+v", snap)
	}
}

func TestWatchUsesBroadcastListener(t *testing.T) {
	mgr := baseline.NewManager(t.TempDir())
	mgr.ApproveReviewedNet(map[string]*baseline.NetPending{gwMAC: {Interface: "eth0", Hosts: map[string]baseline.NetHost{}}}, "test")

	n := New(mgr)
	n.reverseDNS = func(net.IP) string { return "" }
	n.scan = func([]string) (snapshot, error) {
		return snapshot{watched: []string{"eth0"}, networks: map[string]network{"eth0": {key: gwMAC}}}, nil
	}
	n.listen = func(ctx context.Context, iface string, out chan<- sighting) error {
		out <- sighting{iface: iface, mac: mustMAC("ee:ee:ee:ee:ee:01"), source: "DHCP", hostname: "drop-box"}
		<-ctx.Done()
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	alerts, err := n.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case a := <-alerts:
		if a.Metadata["mac"] != "ee:ee:ee:ee:ee:01" || a.Metadata["hostname"] != "drop-box" {
			t.Errorf("unexpected alert %+v", a)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no alert from the broadcast listener")
	}
	cancel()
	for range alerts { // wait for the watcher to stop writing state
	}
}

func TestConfigure(t *testing.T) {
	n := New(nil)
	if err := n.Configure(map[string]interface{}{"poll_interval": "0s"}); err == nil {
		t.Error("zero poll_interval should be rejected")
	}
	if err := n.Configure(map[string]interface{}{"exclude_macs": []interface{}{"nope"}}); err == nil {
		t.Error("bad MAC should be rejected")
	}
}

func TestShippedYAML(t *testing.T) {
	cfgs, err := skills.LoadAvailable("../../../usr/share/fogbot/contrib/skills-available")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cfgs {
		if c.ID != SkillID {
			continue
		}
		n := New(nil)
		if err := n.Configure(c.Config); err != nil {
			t.Fatal(err)
		}
		if n.pollInterval != time.Minute || !n.listenBroadcasts || !n.includeMACVendor || !n.includeReverseDNS || len(n.interfaces) != 0 {
			t.Errorf("unexpected config from shipped YAML: %+v", n)
		}
		return
	}
	t.Fatal("skill 715 not in shipped YAML")
}

// runBPF interprets the instructions broadcastFilter uses
func runBPF(prog []unix.SockFilter, pkt []byte) uint32 {
	var a, x uint32
	ld := func(off uint32, size int) (uint32, bool) {
		if int(off)+size > len(pkt) {
			return 0, false
		}
		switch size {
		case 1:
			return uint32(pkt[off]), true
		default:
			return uint32(binary.BigEndian.Uint16(pkt[off:])), true
		}
	}
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		ok := true
		switch in.Code {
		case 0x28:
			a, ok = ld(in.K, 2)
		case 0x30:
			a, ok = ld(in.K, 1)
		case 0x48:
			a, ok = ld(x+in.K, 2)
		case 0xb1:
			var v uint32
			v, ok = ld(in.K, 1)
			x = 4 * (v & 0xf)
		case 0x15:
			if a == in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case 0x45:
			if a&in.K != 0 {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case 0x06:
			return in.K
		default:
			panic("unknown opcode")
		}
		if !ok {
			return 0
		}
	}
	return 0
}

func TestBroadcastFilter(t *testing.T) {
	arp := ethernet(unix.ETH_P_ARP, make([]byte, 28))
	dhcp := ethernet(unix.ETH_P_IP, udpIP(67, dhcpRequest(make([]byte, 6))))
	other := ethernet(unix.ETH_P_IP, udpIP(53, make([]byte, 20)))
	frag := ethernet(unix.ETH_P_IP, udpIP(67, make([]byte, 20)))
	binary.BigEndian.PutUint16(frag[20:22], 0x0010) // fragment offset
	ipv6 := ethernet(0x86dd, make([]byte, 60))

	for name, c := range map[string]struct {
		pkt  []byte
		pass bool
	}{"arp": {arp, true}, "dhcp": {dhcp, true}, "dns": {other, false}, "fragment": {frag, false}, "ipv6": {ipv6, false}} {
		if got := runBPF(broadcastFilter, c.pkt) != 0; got != c.pass {
			t.Errorf("%s: pass=%v, want %v", name, got, c.pass)
		}
	}
}
