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

func movement(title, location string) notifier.Alert {
	return notifier.Alert{Severity: notifier.SeverityMovement, SkillID: 300, Title: title, Location: location, Activity: "installed " + location}
}

// The bug: MOVEMENT alerts over the burst were only counted into a digest sent
// with the next alert of the kind, so when none came they were never reported.
// A package installed 11th in a batch went unseen.
func TestMovementOverBurstIsDigested(t *testing.T) {
	e := NewEngine(time.Minute, 3, 20)
	defer e.Close()

	sent := 0
	for i := 0; i < 5; i++ {
		if ok, _, _ := e.Process(movement("Package Installed", "dpkg")); ok {
			sent++
		}
	}
	if sent != 3 {
		t.Fatalf("sent %d straight away, want the burst of 3", sent)
	}

	if d := e.Digests(time.Now()); len(d) != 0 {
		t.Fatalf("digest sent before the window ended: %+v", d)
	}
	d := e.Digests(time.Now().Add(time.Minute))
	if len(d) != 1 {
		t.Fatalf("expected one digest for the held-back alerts, got %+v", d)
	}
	if d[0].Title != "Package Installed (digest: 2 more)" || d[0].Location != "dpkg" || d[0].Severity != notifier.SeverityMovement {
		t.Fatalf("unexpected digest %+v", d[0])
	}

	// The window is over, so the next alert goes out at once, not as a digest
	if ok, isDigest, _ := e.Process(movement("Package Installed", "dpkg")); !ok || isDigest {
		t.Fatalf("alert after the digest: sent=%v digest=%v", ok, isDigest)
	}
}

// An alert arriving after the window, before Digests ran, carries the
// held-back count rather than losing it
func TestMovementHeldBackGoesOutWithNextAlert(t *testing.T) {
	e := NewEngine(50*time.Millisecond, 1, 20)
	defer e.Close()

	e.Process(movement("Package Removed", "dpkg"))
	if ok, _, _ := e.Process(movement("Package Removed", "dpkg")); ok {
		t.Fatal("alert over the burst was sent")
	}
	time.Sleep(60 * time.Millisecond)

	ok, isDigest, n := e.Process(movement("Package Removed", "dpkg"))
	if !ok || !isDigest || n != 2 {
		t.Fatalf("expected a digest of 2, got sent=%v digest=%v n=%d", ok, isDigest, n)
	}
	if d := e.Digests(time.Now().Add(time.Second)); len(d) != 0 {
		t.Fatalf("held-back alerts reported twice: %+v", d)
	}
}
