package telegram

import (
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/penguinpowernz/fogbot/internal/auth"
	"github.com/penguinpowernz/fogbot/internal/notifier"
)

func newState(t *testing.T) *auth.State {
	t.Helper()
	s, err := auth.NewState(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAlertChatID_UsesAuthorizedChatOverConfig(t *testing.T) {
	s := newState(t)
	tg := NewTelegram("token", 999, s)

	if id, err := tg.alertChatID(); err != nil || id != 999 {
		t.Fatalf("expected configured fallback 999, got %d, %v", id, err)
	}

	s.Authorize("12345")
	if id, err := tg.alertChatID(); err != nil || id != 12345 {
		t.Fatalf("expected authorized chat 12345, got %d, %v", id, err)
	}

	s.Deauthorize()
	if id, _ := tg.alertChatID(); id != 999 {
		t.Fatalf("expected fallback 999 after deauthorize, got %d", id)
	}
}

func TestAlertChatID_NoChatIsAnError(t *testing.T) {
	tg := NewTelegram("token", 0, newState(t))
	if _, err := tg.alertChatID(); err == nil {
		t.Fatal("expected an error when no chat is authorized or configured")
	}
}

func TestFormatAlert_EscapesMarkdownInFields(t *testing.T) {
	tg := NewTelegram("token", 1, newState(t))
	msg := tg.formatAlert(notifier.Alert{
		Severity:  notifier.SeverityContact,
		Title:     "File Tamper Detected",
		Activity:  "login by www_data running ./x --rev_shell *",
		Location:  "/var/lib/fogbot/suid_baseline.json",
		Unit:      "cmd=`id` [x]",
		Time:      time.Now(),
		SkillID:   500,
		SkillName: "file_watch",
	})

	for _, want := range []string{`www\_data`, `rev\_shell \*`, `suid\_baseline.json`, "cmd=\\`id\\` \\[x]", `file\_watch`} {
		if !strings.Contains(msg, want) {
			t.Errorf("expected %q in message:\n%s", want, msg)
		}
	}
	// The formatter's own bold markers must survive
	if !strings.Contains(msg, "*A:* ") {
		t.Errorf("formatting markers were escaped:\n%s", msg)
	}
}

// The Bot API omits Message on callbacks from inline-mode messages
func TestProcessUpdate_MissingChatDoesNotPanic(t *testing.T) {
	tg := NewTelegram("token", 0, newState(t))

	for _, u := range []Update{
		{Message: &Message{Text: "/start"}},
		{CallbackQuery: &CallbackQuery{ID: "1", Data: "ack:1:x"}},
		{CallbackQuery: &CallbackQuery{ID: "1", Data: "ack:1:x", Message: &Message{}}},
	} {
		if cmd := tg.processUpdate(u); cmd != nil {
			t.Errorf("expected no command for %+v, got %+v", u, cmd)
		}
	}
}

// Transport errors must not carry the request URL, which embeds the bot token
func TestAPICall_ErrorDoesNotLeakToken(t *testing.T) {
	tg := NewTelegram("123456:SECRET-TOKEN", 0, newState(t))
	tg.httpClient.Transport = failingTransport{}

	_, err := tg.apiCall("getUpdates", nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "SECRET-TOKEN") {
		t.Fatalf("error leaks the bot token: %v", err)
	}
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}
