package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/penguinpowernz/fogbot/internal/atomicfile"
	"github.com/penguinpowernz/fogbot/internal/selfwatch"
)

// NetHost is a host seen on a local network, tracked by its MAC address
type NetHost struct {
	MAC       string    `json:"mac"`
	IP        string    `json:"ip,omitempty"` // last IP seen; DHCP moves these around
	Hostname  string    `json:"hostname,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
}

// NetBaseline is the approved hosts on one network
type NetBaseline struct {
	Interface string             `json:"interface"`
	GatewayIP string             `json:"gateway_ip,omitempty"`
	Hosts     map[string]NetHost `json:"hosts"` // by MAC
	// Gateways are other gateway MACs approved for this network, as when the
	// router is replaced; the network stays keyed by its first gateway's MAC
	Gateways   []string  `json:"gateways,omitempty"`
	ApprovedAt time.Time `json:"approved_at"`
	ApprovedBy string    `json:"approved_by,omitempty"`
}

// NetPending is the hosts seen on one network but not yet approved
type NetPending struct {
	Interface string             `json:"interface"`
	GatewayIP string             `json:"gateway_ip,omitempty"`
	Hosts     map[string]NetHost `json:"hosts"` // by MAC
	// Gateways are new gateway MACs seen answering for this network
	Gateways  []string  `json:"gateways,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

const (
	netBaselineFile = "net_baseline.json"
	netPendingFile  = "net_baseline.pending.json"
	netLockFile     = "net_baseline.lock"
)

// withNetLock runs fn holding an exclusive lock on the network baseline files.
// The daemon and `fogbot baseline approve` are separate processes, so m.mu
// alone would let one write back a stale copy over the other's changes.
func (m *Manager) withNetLock(fn func() error) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	f, err := os.OpenFile(filepath.Join(m.stateDir, netLockFile), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("opening baseline lock: %w", err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("locking baseline: %w", err)
	}
	return fn()
}

// LoadNet loads the approved network baselines, keyed by network (the
// gateway's MAC). It returns an empty map if there are none.
func (m *Manager) LoadNet() (map[string]*NetBaseline, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	nets := make(map[string]*NetBaseline)
	return nets, m.readJSON(netBaselineFile, &nets)
}

// LoadPendingNet loads the hosts awaiting approval, keyed by network. It
// returns an empty map if there are none.
func (m *Manager) LoadPendingNet() (map[string]*NetPending, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	nets := make(map[string]*NetPending)
	return nets, m.readJSON(netPendingFile, &nets)
}

// SavePendingNet replaces the hosts awaiting approval
func (m *Manager) SavePendingNet(nets map[string]*NetPending) error {
	return m.withNetLock(func() error {
		return m.writeJSON(netPendingFile, nets)
	})
}

// UpdatePendingNet changes the hosts awaiting approval in place: fn is given
// the approved baselines and the pending hosts as they are on disk, under the
// lock, and the pending hosts are saved after it returns
func (m *Manager) UpdatePendingNet(fn func(approved map[string]*NetBaseline, pending map[string]*NetPending)) error {
	return m.withNetLock(func() error {
		approved := make(map[string]*NetBaseline)
		if err := m.readJSON(netBaselineFile, &approved); err != nil {
			return err
		}
		pending := make(map[string]*NetPending)
		if err := m.readJSON(netPendingFile, &pending); err != nil {
			return err
		}
		fn(approved, pending)
		return m.writeJSON(netPendingFile, pending)
	})
}

// ApproveReviewedNet adds the reviewed pending hosts to the approved baselines,
// creating a network's baseline if it has none, and drops them from the pending
// file. Only the hosts the operator reviewed are approved: the daemon keeps
// adding to the pending file, and a host that joined while the prompt was open
// must not be approved unseen.
func (m *Manager) ApproveReviewedNet(reviewed map[string]*NetPending, approvedBy string) error {
	return m.withNetLock(func() error {
		return m.approveReviewedNet(reviewed, approvedBy)
	})
}

func (m *Manager) approveReviewedNet(reviewed map[string]*NetPending, approvedBy string) error {
	approved := make(map[string]*NetBaseline)
	if err := m.readJSON(netBaselineFile, &approved); err != nil {
		return err
	}
	pending := make(map[string]*NetPending)
	if err := m.readJSON(netPendingFile, &pending); err != nil {
		return err
	}

	now := time.Now()
	for key, rev := range reviewed {
		bl := approved[key]
		if bl == nil {
			bl = &NetBaseline{Hosts: make(map[string]NetHost)}
			approved[key] = bl
		}
		bl.Interface = rev.Interface
		bl.GatewayIP = rev.GatewayIP
		bl.ApprovedAt = now
		bl.ApprovedBy = approvedBy
		for mac, h := range rev.Hosts {
			bl.Hosts[mac] = h
		}
		for _, gw := range rev.Gateways {
			if !slices.Contains(bl.Gateways, gw) {
				bl.Gateways = append(bl.Gateways, gw)
			}
		}

		if p := pending[key]; p != nil {
			for mac := range rev.Hosts {
				delete(p.Hosts, mac)
			}
			p.Gateways = slices.DeleteFunc(p.Gateways, func(gw string) bool { return slices.Contains(rev.Gateways, gw) })
			if len(p.Hosts) == 0 && len(p.Gateways) == 0 {
				delete(pending, key)
			}
		}
	}

	if err := m.writeJSON(netBaselineFile, approved); err != nil {
		return err
	}
	return m.writeJSON(netPendingFile, pending)
}

func (m *Manager) readJSON(name string, v interface{}) error {
	data, err := os.ReadFile(filepath.Join(m.stateDir, name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read %s: %w", name, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("failed to parse %s: %w", name, err)
	}
	return nil
}

func (m *Manager) writeJSON(name string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal %s: %w", name, err)
	}
	path := filepath.Join(m.stateDir, name)
	selfwatch.ExpectWrite(path)
	if err := atomicfile.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write %s: %w", name, err)
	}
	return nil
}
