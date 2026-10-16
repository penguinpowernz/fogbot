package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/penguinpowernz/fogbot/internal/dedup"
	"github.com/penguinpowernz/fogbot/internal/notifier"
)

// slowNotifier blocks every Send until released, like Telegram waiting out a
// rate limit
type slowNotifier struct {
	notifier.Notifier
	release chan struct{}

	mu   sync.Mutex
	sent []notifier.Alert
}

func (n *slowNotifier) Send(ctx context.Context, a notifier.Alert) error {
	select {
	case <-n.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	n.mu.Lock()
	n.sent = append(n.sent, a)
	n.mu.Unlock()
	return nil
}

func (n *slowNotifier) titles() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var titles []string
	for _, a := range n.sent {
		titles = append(titles, a.Title)
	}
	return titles
}

// A slow send must not stop the bus: watchers block on it, and the audit
// tailer throws away events it can't hand to a blocked watcher
func TestProcessAlerts_SlowSendDoesNotBlockBus(t *testing.T) {
	notif := &slowNotifier{release: make(chan struct{})}
	bus := make(chan notifier.Alert)
	engine := dedup.NewEngine(time.Minute, 1000, 1000)
	defer engine.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go processAlerts(ctx, bus, engine, notif, "host")

	for i := 0; i < 50; i++ {
		select {
		case bus <- notifier.Alert{Severity: notifier.SeverityMovement, Title: "t", Location: string(rune('a' + i))}:
		case <-time.After(time.Second):
			t.Fatalf("bus blocked on alert %d while a send was stuck", i)
		}
	}
	close(notif.release)
}

func TestAlertQueue_ReportsDroppedAlerts(t *testing.T) {
	notif := &slowNotifier{release: make(chan struct{})}
	q := newAlertQueue(notif)
	for i := 0; i < alertQueueSize+3; i++ {
		q.add(notifier.Alert{Title: "flood"})
	}
	if q.dropped.Load() != 3 {
		t.Fatalf("dropped = %d, want 3", q.dropped.Load())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	close(notif.release)
	go q.run(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for {
		titles := notif.titles()
		for _, title := range titles {
			if title == "Alerts Dropped" {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no dropped-alerts report after %d sends", len(titles))
		}
		time.Sleep(10 * time.Millisecond)
	}
}
