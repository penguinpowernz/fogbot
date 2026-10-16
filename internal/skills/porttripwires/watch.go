package porttripwires

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
)

// defaultKmsgPath is where the kernel log, and so every iptables LOG line, can
// be read from
const defaultKmsgPath = "/dev/kmsg"

// defaultCooldown is how long a tripwire stays quiet after alerting for the
// same remote address and port. The LOG rules match every packet, not just
// the first, so one connection logs many lines.
const defaultCooldown = 5 * time.Minute

// maxTracked bounds the cooldown table, so a scan from many addresses can't
// grow it without limit
const maxTracked = 10000

// hit is one packet logged by a tripwire rule
type hit struct {
	tripwire tripwire
	proto    string
	src      string
	dst      string
	spt      string
	dpt      string
	iface    string
}

// remote is the address on the other end of the connection
func (h hit) remote() string {
	if h.tripwire.direction == "out" {
		return h.dst
	}
	return h.src
}

// Watch reads the kernel log for packets logged by the tripwire rules and
// alerts on them.
//
// It reads /dev/kmsg rather than kern.log or the journal, so it works whatever
// syslog daemon (if any) is installed. Only records with the kernel facility
// count: root can write to /dev/kmsg too, but its records are tagged as user
// messages, so a fake "fw-510-in:" line can't pose as a tripwire hit.
func (p *PortTripwires) Watch(ctx context.Context) (<-chan notifier.Alert, error) {
	path := p.kmsgPath
	if path == "" {
		path = defaultKmsgPath
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening kernel log %s: %w", path, err)
	}
	// Only packets logged from now on are new; older ones were already
	// reported, or happened while fogbot wasn't watching for them
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, fmt.Errorf("seeking to the end of %s: %w", path, err)
	}

	records := make(chan string, 64)
	done := make(chan struct{})
	go readKmsg(f, records, done)

	alerts := make(chan notifier.Alert, 10)
	go func() {
		defer close(alerts)
		defer f.Close() // unblocks readKmsg
		defer close(done)
		p.watchRecords(ctx, records, alerts)
	}()

	log.Printf("[port-tripwires] Watching %s for %s and %s", path, p.generateRuleID("in"), p.generateRuleID("out"))
	return alerts, nil
}

// readKmsg sends each kernel log record read from f until f is closed. Each
// read of /dev/kmsg returns exactly one record.
func readKmsg(f *os.File, records chan<- string, done <-chan struct{}) {
	defer close(records)

	buf := make([]byte, 8192) // the kernel's limit for one record
	for {
		n, err := f.Read(buf)
		if err != nil {
			// The ring buffer wrapped past records we hadn't read yet; the
			// next read carries on from the oldest record still there
			if errors.Is(err, syscall.EPIPE) {
				log.Printf("[port-tripwires] Kernel log overran, some records were missed")
				continue
			}
			select {
			case <-done:
			default:
				log.Printf("[port-tripwires] Reading kernel log stopped: %v", err)
			}
			return
		}

		select {
		case records <- string(buf[:n]):
		case <-done:
			return
		}
	}
}

// watchRecords turns kernel log records into alerts until ctx ends or records closes
func (p *PortTripwires) watchRecords(ctx context.Context, records <-chan string, alerts chan<- notifier.Alert) {
	cooldown := p.cooldown
	quietUntil := make(map[string]time.Time)

	for {
		select {
		case <-ctx.Done():
			return

		case rec, ok := <-records:
			if !ok {
				return
			}
			h, ok := p.parseRecord(rec)
			if !ok {
				continue
			}

			now := time.Now()
			key := h.tripwire.direction + "|" + h.remote() + "|" + h.dpt
			if until, seen := quietUntil[key]; seen && now.Before(until) {
				continue
			}
			if len(quietUntil) >= maxTracked {
				for k, until := range quietUntil {
					if !now.Before(until) {
						delete(quietUntil, k)
					}
				}
			}
			// Still full: alert anyway rather than go quiet during a flood
			if len(quietUntil) < maxTracked {
				quietUntil[key] = now.Add(cooldown)
			}

			select {
			case alerts <- p.alertFor(h, now):
			case <-ctx.Done():
				return
			}
		}
	}
}

// parseRecord extracts a tripwire hit from a /dev/kmsg record, which looks like
//
//	4,1234,5678901,-;fw-510-in: IN=eth0 OUT= MAC=... SRC=203.0.113.9 DST=192.0.2.1 ... PROTO=TCP SPT=51234 DPT=445 ...
//
// The header before ";" starts with the syslog priority, facility*8 + level.
func (p *PortTripwires) parseRecord(rec string) (hit, bool) {
	// Continuation lines after the first carry key=value metadata, not text
	line, _, _ := strings.Cut(rec, "\n")
	header, msg, ok := strings.Cut(line, ";")
	if !ok {
		return hit{}, false
	}
	prioStr, _, _ := strings.Cut(header, ",")
	prio, err := strconv.Atoi(prioStr)
	if err != nil || prio>>3 != 0 { // 0 is the kernel facility
		return hit{}, false
	}

	var h hit
	found := false
	for _, tw := range tripwires {
		if rest, ok := strings.CutPrefix(msg, p.generateRuleID(tw.direction)+": "); ok {
			h.tripwire, msg, found = tw, rest, true
			break
		}
	}
	if !found {
		return hit{}, false
	}

	for _, field := range strings.Fields(msg) {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue // flags such as SYN or DF
		}
		switch key {
		case "IN":
			if h.tripwire.direction == "in" {
				h.iface = value
			}
		case "OUT":
			if h.tripwire.direction == "out" {
				h.iface = value
			}
		case "SRC":
			h.src = value
		case "DST":
			h.dst = value
		case "PROTO":
			h.proto = strings.ToLower(value)
		case "SPT":
			h.spt = value
		case "DPT":
			h.dpt = value
		}
	}

	if _, err := netip.ParseAddr(h.src); err != nil {
		return hit{}, false
	}
	if _, err := netip.ParseAddr(h.dst); err != nil {
		return hit{}, false
	}
	if port, err := strconv.Atoi(h.dpt); err != nil || port < 1 || port > 65535 {
		return hit{}, false
	}
	return h, true
}

// alertFor builds the alert for a tripwire hit. Every hit is CONTACT: fogbot
// guards developer workstations, which nothing should be connecting to on
// these ports, so an inbound hit is lateral movement or targeted scanning,
// and an outbound one is what malware phoning home looks like.
func (p *PortTripwires) alertFor(h hit, now time.Time) notifier.Alert {
	alert := notifier.Alert{
		Severity:    notifier.SeverityContact,
		Acknowledge: true,
		SkillID:     p.id,
		SkillName:   p.name,
		Size:        "1 connection",
		Location:    fmt.Sprintf("port %s/%s", h.dpt, h.proto),
		Unit:        fmt.Sprintf("src=%s:%s dst=%s:%s", h.src, h.spt, h.dst, h.dpt),
		Time:        now,
		Equipment:   fmt.Sprintf("iptables %s (iface %s)", h.tripwire.chain, h.iface),
		Metadata: map[string]string{
			"direction": h.tripwire.direction,
			"proto":     h.proto,
			"src":       h.src,
			"dst":       h.dst,
			"spt":       h.spt,
			"dpt":       h.dpt,
			"iface":     h.iface,
		},
	}

	if h.tripwire.direction == "out" {
		alert.Title = "Outbound Connection to Tripwire Port"
		alert.Activity = fmt.Sprintf("Outbound %s to %s port %s", strings.ToUpper(h.proto), h.dst, h.dpt)
	} else {
		alert.Title = "Inbound Connection to Tripwire Port"
		alert.Activity = fmt.Sprintf("Inbound %s from %s to port %s", strings.ToUpper(h.proto), h.src, h.dpt)
	}
	return alert
}
