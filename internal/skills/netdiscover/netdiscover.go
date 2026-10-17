package netdiscover

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/penguinpowernz/fogbot/internal/baseline"
	"github.com/penguinpowernz/fogbot/internal/notifier"
	"github.com/penguinpowernz/fogbot/internal/skills"
	"golang.org/x/sys/unix"
)

const (
	SkillID   = 715
	SkillName = "net-discover"
)

// sighting is a host seen on an interface, from the neighbour table or a
// broadcast
type sighting struct {
	iface    string
	mac      net.HardwareAddr
	ip       net.IP
	hostname string
	source   string // "neighbour table", "ARP", "DHCP"
	time     time.Time
}

// network is the network an interface is on, identified by its gateway's MAC
// so that a laptop carried to another network with the same addressing isn't
// compared against home
type network struct {
	key       string
	gatewayIP string
}

// snapshot is what one poll of the system found
type snapshot struct {
	watched  []string           // interfaces to listen on
	networks map[string]network // by interface, where the network is known
	own      map[string]bool    // this host's MACs
	seen     []sighting         // neighbour table entries on watched interfaces
}

// NetDiscover passively learns the hosts on the local network and alerts on
// new ones
type NetDiscover struct {
	mu      sync.RWMutex
	enabled bool
	config  map[string]interface{}

	interfaces        []string
	pollInterval      time.Duration
	listenBroadcasts  bool
	excludeMACs       map[string]bool
	includeMACVendor  bool
	includeReverseDNS bool

	baselineManager *baseline.Manager

	// scan, listen, vendor and reverseDNS are swapped out in tests
	scan       func(interfaces []string) (snapshot, error)
	listen     func(ctx context.Context, iface string, out chan<- sighting) error
	vendor     func(net.HardwareAddr) string
	reverseDNS func(ip net.IP) string
}

// New creates a NetDiscover with the default config
func New(baselineManager *baseline.Manager) *NetDiscover {
	return &NetDiscover{
		pollInterval:      time.Minute,
		listenBroadcasts:  true,
		excludeMACs:       map[string]bool{},
		includeMACVendor:  true,
		includeReverseDNS: true,
		baselineManager:   baselineManager,
		scan:              scanSystem,
		listen:            listenBroadcasts,
		vendor:            macVendor,
		reverseDNS:        lookupName,
	}
}

func (n *NetDiscover) ID() int      { return SkillID }
func (n *NetDiscover) Name() string { return SkillName }
func (n *NetDiscover) Description() string {
	return "Passively learns the hosts on the local network and alerts when a new one appears"
}
func (n *NetDiscover) Why() string {
	return "A device joining your network that you didn't add could be a rogue access point, a drop box, or a neighbour on your Wi-Fi."
}
func (n *NetDiscover) Requires() []string       { return []string{"root"} }
func (n *NetDiscover) Tags() []string           { return []string{"network", "discovery", "baseline"} }
func (n *NetDiscover) DropIns() []skills.DropIn { return nil }
func (n *NetDiscover) SetupHints() []string     { return nil }
func (n *NetDiscover) DeduceCommands(cfg map[string]interface{}) ([]skills.SystemCommand, error) {
	return []skills.SystemCommand{}, nil
}
func (n *NetDiscover) CheckSystemState() (bool, error) { return true, nil }

func (n *NetDiscover) Enabled() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.enabled
}

func (n *NetDiscover) SetEnabled(enabled bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.enabled = enabled
}

func (n *NetDiscover) Config() map[string]interface{} {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config
}

func (n *NetDiscover) Configure(cfg map[string]interface{}) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.config = cfg

	n.interfaces = nil
	if list, ok := cfg["interfaces"].([]interface{}); ok {
		for _, v := range list {
			if s, ok := v.(string); ok && s != "" {
				n.interfaces = append(n.interfaces, s)
			}
		}
	}

	n.pollInterval = time.Minute
	if v, ok := cfg["poll_interval"].(string); ok {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return fmt.Errorf("invalid poll_interval %q", v)
		}
		n.pollInterval = d
	}

	n.excludeMACs = map[string]bool{}
	if list, ok := cfg["exclude_macs"].([]interface{}); ok {
		for _, v := range list {
			s, _ := v.(string)
			mac, err := net.ParseMAC(s)
			if err != nil {
				return fmt.Errorf("invalid MAC %q in exclude_macs", s)
			}
			n.excludeMACs[mac.String()] = true
		}
	}

	n.listenBroadcasts = boolOr(cfg, "listen_broadcasts", true)
	n.includeMACVendor = boolOr(cfg, "include_mac_vendor", true)
	n.includeReverseDNS = boolOr(cfg, "include_reverse_dns", true)
	return nil
}

func boolOr(cfg map[string]interface{}, key string, def bool) bool {
	if v, ok := cfg[key].(bool); ok {
		return v
	}
	return def
}

func (n *NetDiscover) Watch(ctx context.Context) (<-chan notifier.Alert, error) {
	if n.baselineManager == nil {
		return nil, fmt.Errorf("no baseline manager")
	}
	alerts := make(chan notifier.Alert, 10)
	go n.watchLoop(ctx, alerts)
	return alerts, nil
}

// Limits that keep a flood of forged MAC addresses (anyone on the LAN can send
// ARP and DHCP packets with any source MAC) from turning into an alert storm or
// filling memory and the pending baseline
const (
	// floodThreshold is the most new hosts on an approved network in one poll
	// interval before they are reported as one flood rather than one by one
	floodThreshold = 32
	// maxHandled is the most hosts remembered in one run
	maxHandled = 4096
	// maxPendingPerNet is the most hosts awaiting approval on one network
	maxPendingPerNet = 1024
	// maxListenBackoff is the longest wait before restarting a failed listener
	maxListenBackoff = time.Hour
	// recentWindow is how long a host heard broadcasting counts as present
	// when checking whether a gateway is being impersonated
	recentWindow = 10 * time.Minute
	// maxRecentPerIface is the most broadcasting hosts remembered per interface
	maxRecentPerIface = 1024
)

// watcher is the state of one Watch run, owned by its goroutine
type watcher struct {
	*NetDiscover
	alerts   chan<- notifier.Alert
	snap     snapshot
	approved map[string]*baseline.NetBaseline
	// handled holds the hosts already dealt with this run (network|MAC)
	handled map[string]bool
	// learning holds the unapproved networks already announced
	learning map[string]bool
	// adds holds new hosts not yet written to the pending file
	adds map[string]*baseline.NetPending
	// gatewayAlerted holds the gateway MAC changes already reported (iface|MAC)
	gatewayAlerted map[string]bool

	// newThisTick counts new hosts on approved networks this poll interval;
	// flooding is set from the interval it passes floodThreshold until one
	// that doesn't
	newThisTick int
	flooding    bool
	// full is set once maxHandled is reached
	full bool

	listeners map[string]*listenerState
	exits     chan listenerExit

	// recent holds the hosts heard broadcasting lately, by interface then MAC.
	// A host that never talks to this one, such as the real gateway once a
	// spoofer has taken its place in the neighbour table, is only seen here.
	recent map[string]map[string]time.Time
}

// listenerState is a broadcast listener on one interface
type listenerState struct {
	cancel   context.CancelFunc
	stopped  bool
	failures int
	retryAt  time.Time // zero: never, after a permission error
}

type listenerExit struct {
	iface string
	state *listenerState
	err   error
}

func newWatcher(n *NetDiscover, alerts chan<- notifier.Alert) *watcher {
	return &watcher{
		NetDiscover:    n,
		alerts:         alerts,
		approved:       map[string]*baseline.NetBaseline{},
		handled:        map[string]bool{},
		learning:       map[string]bool{},
		adds:           map[string]*baseline.NetPending{},
		gatewayAlerted: map[string]bool{},
		listeners:      map[string]*listenerState{},
		exits:          make(chan listenerExit, 4),
		recent:         map[string]map[string]time.Time{},
	}
}

func (n *NetDiscover) watchLoop(ctx context.Context, alerts chan<- notifier.Alert) {
	defer close(alerts)

	n.mu.RLock()
	interfaces, interval, listen := n.interfaces, n.pollInterval, n.listenBroadcasts
	n.mu.RUnlock()

	w := newWatcher(n, alerts)

	sightings := make(chan sighting, 64)
	defer func() {
		for _, l := range w.listeners {
			l.cancel()
		}
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		w.poll(interfaces)
		if listen {
			w.syncListeners(ctx, sightings, interval)
		}

	wait:
		for {
			select {
			case <-ctx.Done():
				w.flush()
				return
			case s := <-sightings:
				w.remember(s)
				w.observe(s)
			case e := <-w.exits:
				w.listenerExited(e, interval)
			case <-ticker.C:
				break wait
			}
		}

		if w.newThisTick <= floodThreshold {
			w.flooding = false
		}
		w.newThisTick = 0
	}
}

// poll reads the system's networks and neighbour table, and the approved
// baselines (the operator may have approved some since the last poll), then
// writes the hosts found since the last poll to the pending baseline
func (w *watcher) poll(interfaces []string) {
	defer w.flush()

	snap, err := w.scan(interfaces)
	if err != nil {
		log.Printf("[net-discover] %v", err)
		return
	}

	approved, err := w.baselineManager.LoadNet()
	if err != nil {
		log.Printf("[net-discover] Failed to load baseline: %v", err)
		return
	}
	w.snap = snap
	w.approved = approved

	w.expireRecent(time.Now())
	w.checkGateways()
	for _, s := range snap.seen {
		w.observe(s)
	}
}

// checkGateways looks at each interface whose gateway MAC names a network
// with no approved baseline, in case it is an approved network whose gateway
// is being impersonated. ARP spoofing the gateway is how a machine on the LAN
// gets in the middle of this host's traffic; without this check it would
// also put net-discover into learning mode on a "new network" and silence it.
//
// It is the approved network if that network had the same gateway IP and
// this one shows signs of being it: the old gateway's MAC is still present,
// the new gateway MAC belongs to one of its hosts, or two of its hosts are
// here. The interface is then compared against that network's baseline, and
// the change is reported once. A replaced router is accepted by approving it.
func (w *watcher) checkGateways() {
	for iface, nw := range w.snap.networks {
		if nw.gatewayIP == "" || w.approved[nw.key] != nil {
			continue
		}

		seen := map[string]bool{}
		for _, s := range w.snap.seen {
			if s.iface == iface {
				seen[s.mac.String()] = true
			}
		}
		for mac := range w.recent[iface] {
			seen[mac] = true
		}

		keys := make([]string, 0, len(w.approved))
		for key := range w.approved {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		best, bestScore, oldGatewaySeen := "", 0, false
		for _, key := range keys {
			bl := w.approved[key]
			if bl.GatewayIP != nw.gatewayIP {
				continue
			}
			if slices.Contains(bl.Gateways, nw.key) {
				// A gateway MAC the operator approved for this network
				best, bestScore = key, -1
				break
			}
			score := 0
			for mac := range bl.Hosts {
				if mac != nw.key && mac != key && seen[mac] {
					score++
				}
			}
			gwSeen := seen[key]
			_, newGwKnown := bl.Hosts[nw.key]
			if gwSeen || newGwKnown {
				score += 2
			}
			if score >= 2 && score > bestScore {
				best, bestScore, oldGatewaySeen = key, score, gwSeen
			}
		}
		if best == "" {
			continue
		}

		w.snap.networks[iface] = network{key: best, gatewayIP: nw.gatewayIP}
		if bestScore < 0 {
			continue
		}

		ak := iface + "|" + nw.key
		if w.gatewayAlerted[ak] {
			continue
		}
		w.gatewayAlerted[ak] = true
		// Pending as both a gateway and a host, so approving it accepts it as
		// this network's router; reported here only, not as a new host too
		p := w.pendingFor(iface, best)
		p.Gateways = appendNew(p.Gateways, nw.key)
		if _, ok := w.approved[best].Hosts[nw.key]; !ok {
			p.Hosts[nw.key] = baseline.NetHost{MAC: nw.key, IP: nw.gatewayIP, FirstSeen: time.Now()}
		}
		w.handled[best+"|"+nw.key] = true

		evidence := "hosts of the approved network are still here"
		if oldGatewaySeen {
			evidence = "the old gateway " + best + " is still here"
		}
		unit := "mac=" + nw.key
		if w.includeMACVendor {
			if v := w.vendor(mustParseMAC(nw.key)); v != "" {
				unit += " vendor=" + v
			}
		}
		log.Printf("[net-discover] Gateway %s on %s now answers from %s, not %s", nw.gatewayIP, iface, nw.key, best)
		w.alerts <- notifier.Alert{
			Severity:  notifier.SeverityContact,
			SkillID:   SkillID,
			SkillName: SkillName,
			Title:     "Gateway MAC Changed",
			Size:      "1 host",
			Activity:  fmt.Sprintf("Gateway %s answers from a new MAC while %s: possible ARP spoofing", nw.gatewayIP, evidence),
			Location:  networkName(iface, nw),
			Unit:      unit,
			Time:      time.Now(),
			Equipment: "if the router was replaced: sudo fogbot baseline approve",
			Metadata: map[string]string{
				"interface": iface, "gateway_ip": nw.gatewayIP,
				"mac": nw.key, "approved_gateway": best,
			},
			Acknowledge: true,
		}
	}
}

// remember records a host heard broadcasting, whether or not the network it
// is on is known yet. Past maxRecentPerIface (a flood) new hosts are dropped.
func (w *watcher) remember(s sighting) {
	if len(s.mac) != 6 || s.mac[0]&0x01 != 0 || isZero(s.mac) {
		return
	}
	r := w.recent[s.iface]
	if r == nil {
		r = map[string]time.Time{}
		w.recent[s.iface] = r
	}
	mac := s.mac.String()
	if _, ok := r[mac]; !ok && len(r) >= maxRecentPerIface {
		return
	}
	t := s.time
	if t.IsZero() {
		t = time.Now()
	}
	r[mac] = t
}

// expireRecent forgets hosts not heard within recentWindow
func (w *watcher) expireRecent(now time.Time) {
	for iface, r := range w.recent {
		for mac, t := range r {
			if now.Sub(t) > recentWindow {
				delete(r, mac)
			}
		}
		if len(r) == 0 {
			delete(w.recent, iface)
		}
	}
}

// syncListeners runs a broadcast listener on each watched interface,
// restarting one that stopped once its backoff has passed
func (w *watcher) syncListeners(ctx context.Context, out chan<- sighting, interval time.Duration) {
	watched := map[string]bool{}
	for _, iface := range w.snap.watched {
		watched[iface] = true
		if l := w.listeners[iface]; l != nil && (!l.stopped || l.retryAt.IsZero() || time.Now().Before(l.retryAt)) {
			continue
		}
		lctx, cancel := context.WithCancel(ctx)
		l := w.listeners[iface]
		if l == nil {
			l = &listenerState{}
			w.listeners[iface] = l
		}
		l.cancel, l.stopped = cancel, false
		go func(iface string, l *listenerState) {
			log.Printf("[net-discover] Listening for ARP and DHCP broadcasts on %s", iface)
			err := w.listen(lctx, iface, out)
			select {
			case w.exits <- listenerExit{iface: iface, state: l, err: err}:
			case <-ctx.Done(): // the watcher has stopped
			}
		}(iface, l)
	}
	for iface, l := range w.listeners {
		if !watched[iface] {
			l.cancel()
			delete(w.listeners, iface)
		}
	}
}

// listenerExited schedules a restart for a listener that stopped: soon for a
// network error (the interface went down, as on Wi-Fi reconnect or resume),
// with backoff if it keeps failing, and never for a permission error
func (w *watcher) listenerExited(e listenerExit, interval time.Duration) {
	if w.listeners[e.iface] != e.state {
		return // cancelled on purpose
	}
	l := e.state
	l.cancel()
	l.stopped = true
	if e.err == nil {
		l.failures = 0
		l.retryAt = time.Now()
		return
	}
	if errors.Is(e.err, unix.EPERM) || errors.Is(e.err, unix.EACCES) {
		log.Printf("[net-discover] Not listening for broadcasts on %s: %v (needs root); using the neighbour table only", e.iface, e.err)
		l.retryAt = time.Time{}
		return
	}
	backoff := interval << min(l.failures, 10)
	if backoff > maxListenBackoff || backoff <= 0 {
		backoff = maxListenBackoff
	}
	l.failures++
	l.retryAt = time.Now().Add(backoff)
	log.Printf("[net-discover] Broadcast listener on %s stopped: %v; retrying in %s", e.iface, e.err, backoff)
}

// observe records a host. On a network with an approved baseline a host not
// in it raises an alert; on one without, it is only learned.
func (w *watcher) observe(s sighting) {
	if len(s.mac) != 6 || s.mac[0]&0x01 != 0 || isZero(s.mac) {
		return
	}
	mac := s.mac.String()
	if w.snap.own[mac] || w.excludeMACs[mac] {
		return
	}
	nw, ok := w.snap.networks[s.iface]
	if !ok {
		return
	}

	bl := w.approved[nw.key]
	if bl != nil {
		if _, ok := bl.Hosts[mac]; ok {
			return
		}
	}
	hk := nw.key + "|" + mac
	if w.handled[hk] {
		return
	}
	if len(w.handled) >= maxHandled {
		if !w.full {
			w.full = true
			log.Printf("[net-discover] %d hosts seen this run; ignoring further new hosts until restart", maxHandled)
			w.alerts <- w.floodAlert(s.iface, nw, fmt.Sprintf("%d new MAC addresses since fogbot started", maxHandled))
		}
		return
	}
	w.handled[hk] = true

	if bl != nil {
		w.newThisTick++
		if w.newThisTick > floodThreshold {
			if !w.flooding {
				w.flooding = true
				log.Printf("[net-discover] Over %d new hosts on %s in one poll interval; reporting as a flood", floodThreshold, s.iface)
				w.alerts <- w.floodAlert(s.iface, nw, fmt.Sprintf("over %d new MAC addresses in under %s", floodThreshold, w.pollInterval))
			}
			// Not recorded either: approving a flood of forged MACs is no use
			return
		}
	}

	if s.time.IsZero() {
		s.time = time.Now()
	}
	host := baseline.NetHost{MAC: mac, Hostname: s.hostname, FirstSeen: s.time}
	if s.ip != nil {
		host.IP = s.ip.String()
	}
	w.pendingFor(s.iface, nw.key).Hosts[mac] = host

	if bl == nil {
		if !w.learning[nw.key] {
			w.learning[nw.key] = true
			log.Printf("[net-discover] No approved baseline for the network on %s, learning hosts", s.iface)
			w.alerts <- notifier.Alert{
				Severity:  notifier.SeverityNominal,
				SkillID:   SkillID,
				SkillName: SkillName,
				Title:     "Network Baseline Pending Approval",
				Size:      "network",
				Activity:  "Learning the hosts on a network with no approved baseline",
				Location:  networkName(s.iface, nw),
				Unit:      "awaiting approval: sudo fogbot baseline approve",
				Time:      time.Now(),
				Equipment: "baseline-approval",
			}
		}
		return
	}

	log.Printf("[net-discover] New host on %s: %s %s (%s)", s.iface, mac, host.IP, s.source)
	w.alerts <- w.newHostAlert(s, nw)
}

// pendingFor returns the not-yet-written pending entry for a network
func (w *watcher) pendingFor(iface, key string) *baseline.NetPending {
	p := w.adds[key]
	if p == nil {
		p = &baseline.NetPending{Interface: iface, GatewayIP: w.snap.networks[iface].gatewayIP, Hosts: map[string]baseline.NetHost{}}
		w.adds[key] = p
	}
	return p
}

func (w *watcher) floodAlert(iface string, nw network, what string) notifier.Alert {
	return notifier.Alert{
		Severity:    notifier.SeverityContact,
		SkillID:     SkillID,
		SkillName:   SkillName,
		Title:       "MAC Flood on Network",
		Size:        "many hosts",
		Activity:    what + ": possible MAC flooding or an attack tool forging addresses",
		Location:    networkName(iface, nw),
		Unit:        "new hosts are not reported one by one or added to the pending baseline while it lasts",
		Time:        time.Now(),
		Equipment:   "ARP/DHCP from forged MACs",
		Acknowledge: true,
	}
}

func (w *watcher) newHostAlert(s sighting, nw network) notifier.Alert {
	mac := s.mac.String()
	ip := "unknown IP"
	if s.ip != nil {
		ip = s.ip.String()
	}

	unit := []string{"mac=" + mac}
	meta := map[string]string{"mac": mac, "interface": s.iface, "network": nw.key}
	if s.ip != nil {
		meta["ip"] = s.ip.String()
	}
	if w.includeMACVendor {
		if v := w.vendor(s.mac); v != "" {
			unit = append(unit, "vendor="+v)
			meta["vendor"] = v
		}
	}
	if s.hostname != "" {
		unit = append(unit, "dhcp-name="+s.hostname)
		meta["hostname"] = s.hostname
	}
	if w.includeReverseDNS && s.ip != nil {
		if name := w.reverseDNS(s.ip); name != "" {
			unit = append(unit, "rdns="+name)
			meta["rdns"] = name
		}
	}

	return notifier.Alert{
		Severity:    notifier.SeverityContact,
		SkillID:     SkillID,
		SkillName:   SkillName,
		Title:       "New Host on Network",
		Size:        "1 host",
		Activity:    fmt.Sprintf("Unknown host appeared: %s", ip),
		Location:    networkName(s.iface, nw),
		Unit:        strings.Join(unit, " "),
		Time:        s.time,
		Equipment:   fmt.Sprintf("seen in %s; if expected: sudo fogbot baseline approve", s.source),
		Metadata:    meta,
		Acknowledge: true,
	}
}

// flush adds the new hosts and gateways to the pending file, dropping any the
// operator has approved since. It runs under the baseline lock so it can't
// write back a copy older than one `fogbot baseline approve` just saved.
func (w *watcher) flush() {
	if len(w.adds) == 0 {
		return
	}
	dropped := 0
	err := w.baselineManager.UpdatePendingNet(func(approved map[string]*baseline.NetBaseline, pending map[string]*baseline.NetPending) {
		w.approved = approved
		for key, add := range w.adds {
			p := pending[key]
			if p == nil {
				p = &baseline.NetPending{Hosts: map[string]baseline.NetHost{}}
				pending[key] = p
			}
			if p.Hosts == nil {
				p.Hosts = map[string]baseline.NetHost{}
			}
			p.Interface, p.GatewayIP = add.Interface, add.GatewayIP
			for mac, h := range add.Hosts {
				if _, ok := p.Hosts[mac]; ok {
					continue
				}
				if len(p.Hosts) >= maxPendingPerNet {
					dropped++
					continue
				}
				p.Hosts[mac] = h
			}
			for _, gw := range add.Gateways {
				p.Gateways = appendNew(p.Gateways, gw)
			}
			p.UpdatedAt = time.Now()
		}
		for key, p := range pending {
			if bl := approved[key]; bl != nil {
				for mac := range bl.Hosts {
					delete(p.Hosts, mac)
				}
				p.Gateways = slices.DeleteFunc(p.Gateways, func(gw string) bool { return slices.Contains(bl.Gateways, gw) })
			}
			if len(p.Hosts) == 0 && len(p.Gateways) == 0 {
				delete(pending, key)
			}
		}
	})
	if err != nil {
		log.Printf("[net-discover] Failed to save pending baseline: %v", err)
		return
	}
	if dropped > 0 {
		log.Printf("[net-discover] Pending baseline full (%d hosts per network); %d hosts not recorded", maxPendingPerNet, dropped)
	}
	w.adds = map[string]*baseline.NetPending{}
}

func appendNew(list []string, v string) []string {
	if slices.Contains(list, v) {
		return list
	}
	return append(list, v)
}

func mustParseMAC(s string) net.HardwareAddr {
	mac, _ := net.ParseMAC(s)
	return mac
}

func networkName(iface string, nw network) string {
	if nw.gatewayIP == "" {
		return iface
	}
	return fmt.Sprintf("%s (gateway %s)", iface, nw.gatewayIP)
}

func isZero(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}

// lookupName returns the reverse DNS name of ip, or "" if it has none
func lookupName(ip net.IP) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip.String())
	if err != nil || len(names) == 0 {
		return ""
	}
	return cleanHostname(strings.TrimSuffix(names[0], "."))
}

// scanSystem reads the default routes, interfaces and neighbour table
func scanSystem(interfaces []string) (snapshot, error) {
	routes, err := readDefaultRoutes("/proc/net/route")
	if err != nil {
		return snapshot{}, fmt.Errorf("reading routes: %w", err)
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return snapshot{}, fmt.Errorf("listing interfaces: %w", err)
	}
	neighs, err := readNeighbours()
	if err != nil {
		return snapshot{}, err
	}
	return buildSnapshot(interfaces, routes, ifs, neighs), nil
}

// buildSnapshot works out which interfaces to watch, the network each is on,
// and the hosts seen on them
func buildSnapshot(interfaces []string, routes []defaultRoute, ifs []net.Interface, neighs []neighbour) snapshot {
	snap := snapshot{watched: interfaces, networks: map[string]network{}, own: map[string]bool{}}
	if len(snap.watched) == 0 && len(routes) > 0 {
		snap.watched = []string{routes[0].iface}
	}

	names := map[int]string{}
	for _, ifi := range ifs {
		names[ifi.Index] = ifi.Name
		if len(ifi.HardwareAddr) == 6 {
			snap.own[ifi.HardwareAddr.String()] = true
		}
	}

	for _, iface := range snap.watched {
		var gw net.IP
		for _, r := range routes {
			if r.iface == iface {
				gw = r.gateway
				break
			}
		}
		if gw == nil {
			// No gateway to tell networks apart: one baseline per interface
			snap.networks[iface] = network{key: "if:" + iface}
			continue
		}
		for _, nb := range neighs {
			if names[nb.ifindex] == iface && nb.ip.Equal(gw) {
				snap.networks[iface] = network{key: nb.mac.String(), gatewayIP: gw.String()}
				break
			}
		}
		// Gateway not resolved yet: the network is unknown until it is
	}

	for _, nb := range neighs {
		iface := names[nb.ifindex]
		if _, ok := snap.networks[iface]; ok {
			snap.seen = append(snap.seen, sighting{iface: iface, mac: nb.mac, ip: nb.ip, source: "neighbour table"})
		}
	}
	return snap
}
