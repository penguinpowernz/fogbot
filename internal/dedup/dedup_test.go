package dedup

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
)

func TestNewEngine_ZeroWindowDoesNotPanic(t *testing.T) {
	e := NewEngine(0, 0, 0)
	defer e.Close()
	if e.window <= 0 || e.maxBurst <= 0 || e.contactBurst <= 0 {
		t.Fatalf("expected defaults, got window=%v maxBurst=%d contactBurst=%d", e.window, e.maxBurst, e.contactBurst)
	}
}

func contact(title, location string) notifier.Alert {
	return notifier.Alert{Severity: notifier.SeverityContact, SkillID: 510, Title: title, Location: location, Activity: "hit from " + location}
}

// The bug: CONTACT alerts bypassed rate limiting, so a spoofed SYN flood to a
// tripwire port (one alert per source address) queued every later alert,
// from any skill, behind Telegram's rate limit
func TestContactFloodIsDigested(t *testing.T) {
	e := NewEngine(time.Minute, 10, 3)
	defer e.Close()

	sent := 0
	for i := 0; i < 50; i++ {
		if ok, _, _ := e.Process(contact("Inbound Connection", fmt.Sprintf("10.0.0.%d", i))); ok {
			sent++
		}
	}
	if sent != 3 {
		t.Fatalf("sent %d of the flood straight away, want the burst of 3", sent)
	}

	// A different kind of CONTACT alert isn't held back by the flood
	if ok, _, _ := e.Process(contact("Direct Root Login", "from 1.2.3.4")); !ok {
		t.Fatal("an unrelated CONTACT alert was suppressed")
	}

	if d := e.Digests(time.Now()); len(d) != 0 {
		t.Fatalf("digest sent before the window ended: %+v", d)
	}
	d := e.Digests(time.Now().Add(time.Minute))
	if len(d) != 1 {
		t.Fatalf("expected one digest for the flood, got %+v", d)
	}
	if d[0].Severity != notifier.SeverityContact || d[0].Title != "Inbound Connection (digest: 47 more)" || d[0].Size != "47 events" {
		t.Fatalf("unexpected digest %+v", d[0])
	}
	if !strings.HasPrefix(d[0].Location, "10.0.0.3, 10.0.0.4") || !strings.HasSuffix(d[0].Location, "…") {
		t.Fatalf("digest should sample the suppressed locations, got %q", d[0].Location)
	}
	if !strings.Contains(d[0].Activity, "hit from 10.0.0.49") {
		t.Fatalf("digest should carry the latest alert, got %q", d[0].Activity)
	}

	// The flood's window is over, so the next alert goes out at once
	if ok, _, _ := e.Process(contact("Inbound Connection", "10.0.0.99")); !ok {
		t.Fatal("alert after the digest was suppressed")
	}
	if d := e.Digests(time.Now().Add(2 * time.Minute)); len(d) != 0 {
		t.Fatalf("digest with nothing suppressed: %+v", d)
	}
}
