package auditlog

import (
	"fmt"
	"time"

	"github.com/penguinpowernz/fogbot/internal/notifier"
)

// DroppedCheckInterval is how often subscribers should check TakeDropped
const DroppedCheckInterval = 10 * time.Second

// DroppedAlert reports audit events for a skill's rule key that were thrown
// away because the skill wasn't keeping up. Whatever they recorded went
// unchecked, so this is CONTACT: a flood of events is also how someone would
// hide the one that matters.
func DroppedAlert(n uint64, skillID int, skillName, key string) notifier.Alert {
	return notifier.Alert{
		Severity:    notifier.SeverityContact,
		SkillID:     skillID,
		SkillName:   skillName,
		Title:       "Audit Events Dropped",
		Size:        fmt.Sprintf("%d events", n),
		Activity:    fmt.Sprintf("%d audit events for %s arrived faster than they could be checked and were not examined", n, skillName),
		Location:    "audit key " + key,
		Unit:        "check /var/log/audit/audit.log for: ausearch -k " + key,
		Time:        time.Now(),
		Equipment:   "audit-tailer",
		Acknowledge: true,
	}
}
