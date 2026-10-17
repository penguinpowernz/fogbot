package netdiscover

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/penguinpowernz/fogbot/internal/baseline"
	"github.com/penguinpowernz/fogbot/internal/notifier"
	"golang.org/x/sys/unix"
)

// approveHome approves gwMAC's network on eth0 with the gateway and two hosts
func approveHome(t *testing.T, mgr *baseline.Manager) {
	t.Helper()
	hosts := map[string]baseline.NetHost{}
	for _, mac := range []string{gwMAC, "aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:02"} {
		hosts[mac] = baseline.NetHost{MAC: mac}
	}
	err := mgr.ApproveReviewedNet(map[string]*baseline.NetPending{gwMAC: {Interface: "eth0", GatewayIP: "192.168.1.1", Hosts: hosts}}, "test")
	if err != nil {
		t.Fatal(err)
	}
}

// pollWith runs one poll against a neighbour table on eth0 whose gateway
// 192.168.1.1 answers from gw
func pollWith(w *watcher, gw string, macs ...string) {
	seen := []sighting{{iface: "eth0", mac: mustMAC(gw), ip: net.ParseIP("192.168.1.1"), source: "neighbour table"}}
	for i, mac := range macs {
		seen = append(seen, sighting{iface: "eth0", mac: mustMAC(mac), ip: net.IPv4(192, 168, 1, byte(10+i)), source: "neighbour table"})
	}
	w.scan = func([]string) (snapshot, error) {
		return snapshot{
			watched:  []string{"eth0"},
			networks: map[string]network{"eth0": {key: gw, gatewayIP: "192.168.1.1"}},
			own:      map[string]bool{},
			seen:     seen,
		}, nil
	}
	w.poll(nil)
}

func titles(alerts []notifier.Alert) []string {
	var out []string
	for _, a := range alerts {
		out = append(out, a.Severity+":"+a.Title)
	}
	return out
}

func TestSpoofedGatewayIsReportedNotLearned(t *testing.T) {
	w, alerts, mgr := testWatcher(t)
	approveHome(t, mgr)

	const attacker = "c4:00:00:00:00:66"
	pollWith(w, attacker, "aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:02", "c4:00:00:00:00:77")

	got := titles(drain(alerts))
	want := []string{"contact:Gateway MAC Changed", "contact:New Host on Network"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if w.snap.networks["eth0"].key != gwMAC {
		t.Errorf("eth0 should still be compared against the approved network")
	}

	// Reported once
	pollWith(w, attacker, "aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:02")
	if got := drain(alerts); len(got) != 0 {
		t.Errorf("expected no repeat alerts, got %v", titles(got))
	}

	// The operator accepts it as a replaced router
	pending, _ := mgr.LoadPendingNet()
	if p := pending[gwMAC]; p == nil || len(p.Gateways) != 1 || p.Gateways[0] != attacker {
		t.Fatalf("new gateway should be pending, got %+v", pending)
	}
	if err := mgr.ApproveReviewedNet(pending, "test"); err != nil {
		t.Fatal(err)
	}
	w2, alerts2, _ := testWatcher(t)
	w2.baselineManager = mgr
	pollWith(w2, attacker, "aa:aa:aa:aa:aa:01")
	if got := drain(alerts2); len(got) != 0 {
		t.Errorf("approved gateway should be quiet, got %v", titles(got))
	}
	if w2.snap.networks["eth0"].key != gwMAC {
		t.Errorf("approved gateway should map to the approved network")
	}
}

func TestOldGatewayStillPresentIsSpoofing(t *testing.T) {
	w, alerts, mgr := testWatcher(t)
	approveHome(t, mgr)
	// Only the real gateway is visible, at another IP
	pollWith(w, "c4:00:00:00:00:66", gwMAC)
	if got := titles(drain(alerts)); len(got) == 0 || got[0] != "contact:Gateway MAC Changed" {
		t.Errorf("got %v", got)
	}
}

func TestOtherNetworkWithSameGatewayIPIsLearned(t *testing.T) {
	w, alerts, mgr := testWatcher(t)
	approveHome(t, mgr)
	// A café on the same 192.168.1.0/24: none of the home hosts
	pollWith(w, "c4:00:00:00:00:99", "c4:00:00:00:00:01", "c4:00:00:00:00:02")
	got := titles(drain(alerts))
	if len(got) != 1 || got[0] != "nominal:Network Baseline Pending Approval" {
		t.Errorf("got %v", got)
	}
}

func TestFloodIsReportedOnce(t *testing.T) {
	w, _, mgr := testWatcher(t)
	approveHome(t, mgr)
	w.approved, _ = mgr.LoadNet()
	out := make(chan notifier.Alert, 100)
	w.alerts = out

	for i := 0; i < floodThreshold+20; i++ {
		w.observe(sighting{iface: "eth0", mac: net.HardwareAddr{0xc4, 0, 0, 0, byte(i >> 8), byte(i)}})
	}
	w.flush()

	got := drain(out)
	floods := 0
	for _, a := range got {
		if a.Title == "MAC Flood on Network" {
			floods++
		}
	}
	if floods != 1 || len(got) != floodThreshold+1 {
		t.Errorf("expected %d host alerts and one flood alert, got %d alerts, %d floods", floodThreshold, len(got), floods)
	}
	pending, _ := mgr.LoadPendingNet()
	if n := len(pending[gwMAC].Hosts); n != floodThreshold {
		t.Errorf("flooded hosts should not be pending, got %d", n)
	}
}

func TestListenerRestartsAfterNetworkError(t *testing.T) {
	w, _, _ := testWatcher(t)
	starts := make(chan int, 4)
	calls := 0
	w.listen = func(ctx context.Context, iface string, out chan<- sighting) error {
		calls++
		starts <- calls
		if calls == 1 {
			return fmt.Errorf("recvfrom: %w", unix.ENETDOWN)
		}
		<-ctx.Done()
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w.syncListeners(ctx, nil, time.Millisecond)
	<-starts
	w.listenerExited(<-w.exits, time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	w.syncListeners(ctx, nil, time.Millisecond)
	select {
	case <-starts:
	case <-time.After(time.Second):
		t.Fatal("listener was not restarted")
	}
}

func TestListenerNotRetriedWithoutPermission(t *testing.T) {
	w, _, _ := testWatcher(t)
	calls := 0
	w.listen = func(context.Context, string, chan<- sighting) error {
		calls++
		return fmt.Errorf("opening raw socket: %w", unix.EPERM)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w.syncListeners(ctx, nil, time.Millisecond)
	w.listenerExited(<-w.exits, time.Millisecond)
	w.syncListeners(ctx, nil, time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	if calls != 1 {
		t.Errorf("expected no retry after EPERM, got %d starts", calls)
	}
}

func TestFlushDoesNotResurrectHostsApprovedMeanwhile(t *testing.T) {
	w, _, mgr := testWatcher(t)
	approveHome(t, mgr)
	w.approved, _ = mgr.LoadNet()

	w.observe(sighting{iface: "eth0", mac: mustMAC("c4:00:00:00:00:01")})
	w.flush()
	w.observe(sighting{iface: "eth0", mac: mustMAC("c4:00:00:00:00:02")})

	// The operator approves the first host before the daemon's next flush;
	// the daemon's copy of the approved baseline is now stale
	pending, _ := mgr.LoadPendingNet()
	if err := mgr.ApproveReviewedNet(pending, "test"); err != nil {
		t.Fatal(err)
	}
	w.flush()

	pending, _ = mgr.LoadPendingNet()
	if _, ok := pending[gwMAC].Hosts["c4:00:00:00:00:01"]; ok {
		t.Error("approved host is pending again")
	}
	if _, ok := pending[gwMAC].Hosts["c4:00:00:00:00:02"]; !ok {
		t.Error("new host missing from pending")
	}
}

func TestOldGatewayHeardBroadcastingIsSpoofing(t *testing.T) {
	w, alerts, mgr := testWatcher(t)
	// Only the gateway is approved, so no hosts to recognise the network by
	err := mgr.ApproveReviewedNet(map[string]*baseline.NetPending{gwMAC: {Interface: "eth0", GatewayIP: "192.168.1.1",
		Hosts: map[string]baseline.NetHost{gwMAC: {MAC: gwMAC}}}}, "test")
	if err != nil {
		t.Fatal(err)
	}

	// The spoofer has replaced the gateway in the neighbour table, but the
	// real gateway is still heard sending ARP
	w.remember(sighting{iface: "eth0", mac: mustMAC(gwMAC), source: "ARP", time: time.Now()})
	pollWith(w, "c4:00:00:00:00:66")
	if got := titles(drain(alerts)); len(got) == 0 || got[0] != "contact:Gateway MAC Changed" {
		t.Errorf("got %v", got)
	}
}

func TestRecentBroadcastsExpire(t *testing.T) {
	w, _, _ := testWatcher(t)
	now := time.Now()
	w.remember(sighting{iface: "eth0", mac: mustMAC(gwMAC), time: now.Add(-recentWindow - time.Second)})
	w.remember(sighting{iface: "eth0", mac: mustMAC("aa:aa:aa:aa:aa:01"), time: now})
	w.expireRecent(now)
	if _, ok := w.recent["eth0"][gwMAC]; ok || len(w.recent["eth0"]) != 1 {
		t.Errorf("got %v", w.recent)
	}

	for i := 0; i < maxRecentPerIface+10; i++ {
		w.remember(sighting{iface: "eth1", mac: net.HardwareAddr{0xc4, 0, 0, 0, byte(i >> 8), byte(i)}})
	}
	if n := len(w.recent["eth1"]); n != maxRecentPerIface {
		t.Errorf("expected the cap to hold, got %d", n)
	}
}
