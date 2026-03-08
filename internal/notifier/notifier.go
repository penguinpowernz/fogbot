package notifier

import (
	"context"
	"time"
)

// Severity levels for alerts
const (
	SeverityNominal  = "nominal"  // 🟢 lifecycle events
	SeverityMovement = "movement" // 🟡 rate-limited digests
	SeverityContact  = "contact"  // 🔴 immediate single alerts
)

// Alert represents a detection event to be sent to the operator
type Alert struct {
	Severity    string            // nominal, movement, contact
	SkillID     int               // which skill triggered this
	SkillName   string            // human-readable skill name
	Title       string            // e.g. "File Integrity", "SSH Brute Force"
	Size        string            // SALUTE: Size - how many actors/processes
	Activity    string            // SALUTE: Activity - what happened
	Location    string            // SALUTE: Location - where (file path, IP, etc)
	Unit        string            // SALUTE: Unit - who did it (uid, process chain)
	Time        time.Time         // SALUTE: Time - when
	Equipment   string            // SALUTE: Equipment - how (tool/method used)
	Host        string            // hostname for this alert
	Metadata    map[string]string // additional context for drill-down
	Acknowledge bool              // if true, show acknowledge button
}

// Command represents an inbound operator command
type Command struct {
	Raw        string   // raw text from operator
	ChatID     string   // implementation-specific sender ID
	Args       []string // parsed tokens
	Verb       string   // parsed command verb
	CallbackID string   // for inline keyboard callbacks
}

// Known command verbs
const (
	CmdStart    = "start"    // initiate auth
	CmdApprove  = "approve"  // approve pending baseline
	CmdStatus   = "status"   // request status summary
	CmdAck      = "ack"      // acknowledge alert
	CmdHi       = "hi"       // ping
	CmdHello    = "hello"    // ping
	CmdDrillIn  = "drillin"  // drill into status section
	CmdDrillOut = "drillout" // return to status summary
)

// Notifier handles outbound alerts and inbound operator commands
type Notifier interface {
	// Send pushes an alert to the operator
	Send(ctx context.Context, alert Alert) error

	// Commands returns a channel of inbound operator commands
	// Each implementation handles its own polling/event loop
	Commands(ctx context.Context) (<-chan Command, error)

	// Name of this notifier implementation
	Name() string

	// Close shuts down the notifier cleanly
	Close() error
}
