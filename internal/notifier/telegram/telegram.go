package telegram

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/penguinpowernz/fogbot/internal/auth"
	"github.com/penguinpowernz/fogbot/internal/notifier"
)

const (
	apiBase      = "https://api.telegram.org/bot"
	pollTimeout  = 30 // long polling timeout in seconds
	pollInterval = 1 * time.Second
)

// Telegram implements the Notifier interface for Telegram
type Telegram struct {
	token      string
	chatID     int64
	httpClient *http.Client
	authState  *auth.State
	rateLimiter *auth.RateLimiter
	lastUpdateID int64
}

// NewTelegram creates a new Telegram notifier
func NewTelegram(token string, chatID int64, authState *auth.State) *Telegram {
	// Create HTTP client with proper TLS configuration
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			// Use system certificate pool
			MinVersion: tls.VersionTLS12,
		},
	}

	// For testing only: allow skipping TLS verification
	// DO NOT use in production!
	if os.Getenv("FOGBOT_INSECURE_TLS") == "true" {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	httpClient := &http.Client{
		Timeout:   60 * time.Second,
		Transport: transport,
	}

	return &Telegram{
		token:       token,
		chatID:      chatID,
		httpClient:  httpClient,
		authState:   authState,
		rateLimiter: auth.NewRateLimiter(10, 3, 60*time.Second),
	}
}

// Name returns the notifier name
func (t *Telegram) Name() string {
	return "telegram"
}

// Send sends an alert to Telegram
func (t *Telegram) Send(ctx context.Context, alert notifier.Alert) error {
	message := t.formatAlert(alert)

	params := url.Values{}
	params.Set("chat_id", strconv.FormatInt(t.chatID, 10))
	params.Set("text", message)
	params.Set("parse_mode", "Markdown")

	// Add inline keyboard for acknowledge button if requested
	if alert.Acknowledge && alert.Severity == notifier.SeverityContact {
		keyboard := t.makeAckButton(alert.SkillID)
		params.Set("reply_markup", keyboard)
	}

	_, err := t.apiCall("sendMessage", params)
	return err
}

// SendText sends a plain text message to a specific chat (for command responses)
func (t *Telegram) SendText(ctx context.Context, chatID, text string) error {
	// Parse chatID string to int64
	var targetChatID int64
	var err error
	if chatID != "" {
		targetChatID, err = strconv.ParseInt(chatID, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid chat ID '%s': %w", chatID, err)
		}
	} else {
		targetChatID = t.chatID
	}

	// Debug logging
	fmt.Printf("[DEBUG] SendText: input chatID='%s', parsed=%d, struct chatID=%d, text='%s'\n",
		chatID, targetChatID, t.chatID, text)

	params := url.Values{}
	params.Set("chat_id", strconv.FormatInt(targetChatID, 10))
	params.Set("text", text)

	_, err = t.apiCall("sendMessage", params)
	if err != nil {
		return fmt.Errorf("sendMessage to %d failed: %w", targetChatID, err)
	}
	return nil
}

// UpdateChatID updates the default chat ID for this notifier (called after authorization)
func (t *Telegram) UpdateChatID(chatID string) error {
	newChatID, err := strconv.ParseInt(chatID, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid chat ID: %w", err)
	}
	t.chatID = newChatID
	return nil
}

// Commands returns a channel of inbound commands
func (t *Telegram) Commands(ctx context.Context) (<-chan notifier.Command, error) {
	ch := make(chan notifier.Command, 10)

	go t.pollLoop(ctx, ch)

	return ch, nil
}

// pollLoop runs the long polling loop for incoming messages
func (t *Telegram) pollLoop(ctx context.Context, ch chan<- notifier.Command) {
	defer close(ch)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		updates, err := t.getUpdates(ctx)
		if err != nil {
			// Log error and continue
			time.Sleep(pollInterval)
			continue
		}

		for _, update := range updates {
			if update.UpdateID > t.lastUpdateID {
				t.lastUpdateID = update.UpdateID
			}

			cmd := t.processUpdate(update)
			if cmd != nil {
				select {
				case ch <- *cmd:
				case <-ctx.Done():
					return
				}
			}
		}

		time.Sleep(pollInterval)
	}
}

// getUpdates fetches new updates from Telegram
func (t *Telegram) getUpdates(ctx context.Context) ([]Update, error) {
	params := url.Values{}
	params.Set("offset", strconv.FormatInt(t.lastUpdateID+1, 10))
	params.Set("timeout", strconv.Itoa(pollTimeout))

	data, err := t.apiCall("getUpdates", params)
	if err != nil {
		return nil, err
	}

	var response struct {
		Ok     bool     `json:"ok"`
		Result []Update `json:"result"`
	}

	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("unmarshaling updates: %w", err)
	}

	return response.Result, nil
}

// processUpdate converts a Telegram update to a Command
func (t *Telegram) processUpdate(update Update) *notifier.Command {
	var text string
	var chatID int64
	var callbackID string

	if update.Message != nil {
		text = update.Message.Text
		chatID = update.Message.Chat.ID
	} else if update.CallbackQuery != nil {
		text = update.CallbackQuery.Data
		chatID = update.CallbackQuery.Message.Chat.ID
		callbackID = update.CallbackQuery.ID
	} else {
		return nil
	}

	chatIDStr := strconv.FormatInt(chatID, 10)

	// Check if authorized
	isAuth := t.authState.IsAuthorized(chatIDStr)

	// Rate limiting
	if isAuth {
		if !t.rateLimiter.CheckAuthorized(chatIDStr) {
			return nil // exceeded rate limit
		}
	} else {
		if !t.rateLimiter.CheckUnauthorized(chatIDStr) {
			return nil // exceeded unauth budget
		}
	}

	// Sanitize input
	text = auth.Sanitize(text)

	// Parse command
	args := strings.Fields(text)
	if len(args) == 0 {
		return nil
	}

	verb := strings.TrimPrefix(strings.ToLower(args[0]), "/")

	return &notifier.Command{
		Raw:        text,
		ChatID:     chatIDStr,
		Args:       args,
		Verb:       verb,
		CallbackID: callbackID,
	}
}

// formatAlert formats an alert as a Telegram message
func (t *Telegram) formatAlert(alert notifier.Alert) string {
	var emoji string
	var severityText string

	switch alert.Severity {
	case notifier.SeverityContact:
		emoji = "🔴"
		severityText = "CONTACT"
	case notifier.SeverityMovement:
		emoji = "🟡"
		severityText = "MOVEMENT"
	case notifier.SeverityNominal:
		emoji = "🟢"
		severityText = "NOMINAL"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s *[%s]* %s\n", emoji, severityText, alert.Title))
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━\n")

	if alert.Size != "" {
		sb.WriteString(fmt.Sprintf("*S:* %s\n", alert.Size))
	}
	if alert.Activity != "" {
		sb.WriteString(fmt.Sprintf("*A:* %s\n", alert.Activity))
	}
	if alert.Location != "" {
		sb.WriteString(fmt.Sprintf("*L:* %s\n", alert.Location))
	}
	if alert.Unit != "" {
		sb.WriteString(fmt.Sprintf("*U:* %s\n", alert.Unit))
	}
	sb.WriteString(fmt.Sprintf("*T:* %s\n", alert.Time.UTC().Format("2006-01-02 15:04:05 UTC")))
	if alert.Equipment != "" {
		sb.WriteString(fmt.Sprintf("*E:* %s\n", alert.Equipment))
	}

	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━\n")
	sb.WriteString(fmt.Sprintf("Host: %s", alert.Host))

	if alert.SkillID > 0 {
		sb.WriteString(fmt.Sprintf("  |  skill #%d %s", alert.SkillID, alert.SkillName))
	}

	return sb.String()
}

// makeAckButton creates an inline keyboard with acknowledge button
func (t *Telegram) makeAckButton(skillID int) string {
	// Simplified - in production would use proper callback signing
	callback := auth.SignCallback("ack", strconv.Itoa(skillID), t.token)
	keyboard := map[string]interface{}{
		"inline_keyboard": [][]map[string]string{
			{
				{"text": "✓ Acknowledge", "callback_data": callback},
			},
		},
	}

	data, err := json.Marshal(keyboard)
	if err != nil {
		log.Printf("Failed to marshal keyboard JSON: %v", err)
		return ""
	}
	return string(data)
}

// apiCall makes a call to the Telegram Bot API
func (t *Telegram) apiCall(method string, params url.Values) ([]byte, error) {
	apiURL := fmt.Sprintf("%s%s/%s", apiBase, t.token, method)

	resp, err := t.httpClient.PostForm(apiURL, params)
	if err != nil {
		// Provide more detailed error for common issues
		return nil, fmt.Errorf("api call failed (check network/TLS certs): %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api returned status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// Close shuts down the Telegram notifier
func (t *Telegram) Close() error {
	// Nothing to clean up
	return nil
}

// Update represents a Telegram update
type Update struct {
	UpdateID      int64          `json:"update_id"`
	Message       *Message       `json:"message"`
	CallbackQuery *CallbackQuery `json:"callback_query"`
}

// Message represents a Telegram message
type Message struct {
	MessageID int64  `json:"message_id"`
	From      *User  `json:"from"`
	Chat      *Chat  `json:"chat"`
	Date      int64  `json:"date"`
	Text      string `json:"text"`
}

// CallbackQuery represents a callback query from an inline button
type CallbackQuery struct {
	ID      string   `json:"id"`
	From    *User    `json:"from"`
	Message *Message `json:"message"`
	Data    string   `json:"data"`
}

// User represents a Telegram user
type User struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Username  string `json:"username"`
}

// Chat represents a Telegram chat
type Chat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}
