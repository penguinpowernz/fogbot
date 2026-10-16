package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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

// Fields such as a process command line are attacker controlled; an oversized
// or non-UTF-8 field must not make Telegram reject the whole alert
func TestFormatAlert_CapsAndCleansHostileFields(t *testing.T) {
	tg := NewTelegram("token", 1, newState(t))
	msg := tg.formatAlert(notifier.Alert{
		Severity:  notifier.SeverityContact,
		Title:     "Suspicious Process Execution",
		Activity:  "bad\xffutf8\nHost: fake",
		Equipment: strings.Repeat("A", 10000),
		Time:      time.Now(),
	})

	if !utf8.ValidString(msg) {
		t.Error("message is not valid UTF-8")
	}
	if n := utf8.RuneCountInString(msg); n > 4096 {
		t.Errorf("message is %d characters, over Telegram's 4096 limit", n)
	}
	if strings.Contains(msg, "\nHost: fake") {
		t.Errorf("a field started a new line:\n%s", msg)
	}
}

// scriptedTransport answers each request with the next status in statuses
type scriptedTransport struct {
	statuses []int
	bodies   []string
	calls    int
}

func (s *scriptedTransport) RoundTrip(*http.Request) (*http.Response, error) {
	i := s.calls
	s.calls++
	if i >= len(s.statuses) {
		i = len(s.statuses) - 1
	}
	body := `{"ok":true,"result":{}}`
	if i < len(s.bodies) && s.bodies[i] != "" {
		body = s.bodies[i]
	}
	return &http.Response{
		StatusCode: s.statuses[i],
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}, nil
}

// A rate limit or server error must not lose the alert
func TestSend_RetriesTemporaryFailures(t *testing.T) {
	defer func(d time.Duration) { retryBackoff = d }(retryBackoff)
	retryBackoff = time.Millisecond

	tr := &scriptedTransport{
		statuses: []int{http.StatusTooManyRequests, http.StatusBadGateway, http.StatusOK},
		bodies:   []string{`{"ok":false,"error_code":429,"parameters":{"retry_after":0}}`},
	}
	tg := NewTelegram("token", 1, newState(t))
	tg.httpClient.Transport = tr

	alert := notifier.Alert{Severity: notifier.SeverityContact, Title: "x", Time: time.Now()}
	if err := tg.Send(context.Background(), alert); err != nil {
		t.Fatalf("expected the alert to be delivered after retries, got %v", err)
	}
	if tr.calls != 3 {
		t.Fatalf("expected 3 calls, got %d", tr.calls)
	}
}

// A request Telegram refuses outright is not retried as-is
func TestSend_DoesNotRetryRefusedRequest(t *testing.T) {
	tr := &scriptedTransport{statuses: []int{http.StatusForbidden}}
	tg := NewTelegram("token", 1, newState(t))
	tg.httpClient.Transport = tr

	alert := notifier.Alert{Severity: notifier.SeverityContact, Title: "x", Time: time.Now()}
	if err := tg.Send(context.Background(), alert); err == nil {
		t.Fatal("expected an error")
	}
	if tr.calls != 1 {
		t.Fatalf("expected 1 call, got %d", tr.calls)
	}
}

func TestRetryAfter(t *testing.T) {
	e := &apiError{status: 429, body: `{"ok":false,"error_code":429,"parameters":{"retry_after":7}}`}
	if d, ok := retryDelay(e, 1); !ok || d != 7*time.Second {
		t.Fatalf("expected 7s retry, got %v %v", d, ok)
	}
	e.body = `{"parameters":{"retry_after":3600}}`
	if d, _ := retryDelay(e, 1); d != maxRetryWait {
		t.Fatalf("expected retry capped at %v, got %v", maxRetryWait, d)
	}
}

// In a group chat commands arrive as /command@botname
func TestProcessUpdate_StripsBotMention(t *testing.T) {
	tg := NewTelegram("token", 0, newState(t))
	cmd := tg.processUpdate(Update{Message: &Message{Text: "/status@fog_bot", Chat: &Chat{ID: 1}}})
	if cmd == nil || cmd.Verb != "status" {
		t.Fatalf("expected verb status, got %+v", cmd)
	}
}

// recordingTransport records each request's method and form, answering 200
type recordingTransport struct {
	methods []string
	forms   []url.Values
}

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.ParseForm()
	r.methods = append(r.methods, req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:])
	r.forms = append(r.forms, req.PostForm)
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"ok":true,"result":true}`)), Header: make(http.Header)}, nil
}

// The bug: presses of an alert's Acknowledge button were never answered, so
// the button span forever, and the signed token was never checked
func TestProcessUpdate_AckButton(t *testing.T) {
	s := newState(t)
	s.Authorize("42")
	tr := &recordingTransport{}
	tg := NewTelegram("token", 0, s)
	tg.httpClient.Transport = tr

	press := func(chat int64, data string) *notifier.Command {
		return tg.processUpdate(Update{CallbackQuery: &CallbackQuery{ID: "cb1", Data: data,
			Message: &Message{MessageID: 7, Chat: &Chat{ID: chat}}}})
	}

	cmd := press(42, tg.makeAckButtonData(510))
	if cmd == nil || cmd.Verb != notifier.CmdAck || len(cmd.Args) != 2 || cmd.Args[1] != "510" {
		t.Fatalf("expected an ack for skill 510, got %+v", cmd)
	}
	if len(tr.methods) != 2 || tr.methods[0] != "answerCallbackQuery" || tr.methods[1] != "editMessageReplyMarkup" {
		t.Fatalf("expected the callback answered and button removed, got %v", tr.methods)
	}
	if tr.forms[0].Get("callback_query_id") != "cb1" || tr.forms[1].Get("message_id") != "7" {
		t.Fatalf("unexpected requests %v", tr.forms)
	}

	// A forged token, or a press from another chat, does nothing
	tr.methods = nil
	if cmd := press(42, "ack:510:0000000000000000"); cmd != nil {
		t.Fatalf("forged callback accepted: %+v", cmd)
	}
	if cmd := press(99, tg.makeAckButtonData(510)); cmd != nil {
		t.Fatalf("callback from an unauthorized chat accepted: %+v", cmd)
	}
	if len(tr.methods) != 0 {
		t.Fatalf("API called for rejected callbacks: %v", tr.methods)
	}
}

// makeAckButtonData returns the callback data makeAckButton puts on the button
func (t *Telegram) makeAckButtonData(skillID int) string {
	var kb struct {
		InlineKeyboard [][]struct {
			CallbackData string `json:"callback_data"`
		} `json:"inline_keyboard"`
	}
	json.Unmarshal([]byte(t.makeAckButton(skillID)), &kb)
	return kb.InlineKeyboard[0][0].CallbackData
}

// Replies are Markdown, falling back to plain text if Telegram rejects it
func TestSendText_MarkdownWithFallback(t *testing.T) {
	tr := &scriptedTransport{statuses: []int{http.StatusBadRequest, http.StatusOK}}
	tg := NewTelegram("token", 1, newState(t))
	tg.httpClient.Transport = tr

	if err := tg.SendText(context.Background(), "1", "*Status* host_1"); err != nil {
		t.Fatalf("expected the plain-text retry to succeed, got %v", err)
	}
	if tr.calls != 2 {
		t.Fatalf("expected 2 calls, got %d", tr.calls)
	}
}
