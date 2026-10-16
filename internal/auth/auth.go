package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/penguinpowernz/fogbot/internal/atomicfile"
	"github.com/penguinpowernz/fogbot/internal/selfwatch"
)

const (
	// FOG-XXXX-XXXX format
	CodePattern = `^FOG-[A-Z0-9]{4}-[A-Z0-9]{4}$`
)

var (
	codeRegex = regexp.MustCompile(CodePattern)
)

// State persists authorization information
type State struct {
	mu             sync.RWMutex
	AuthorizedChat string    `json:"authorized_chat"`
	AuthorizedAt   time.Time `json:"authorized_at"`
	Code           string    `json:"-"` // never persisted
	CodeUsed       bool      `json:"code_used"`
	path           string
	pendingAuth    map[string]time.Time // chats waiting for auth code
}

// RateLimiter tracks message rates from chat IDs
type RateLimiter struct {
	mu         sync.Mutex
	authorized map[string]*rateBucket
	unauth     map[string]*rateBucket
	maxAuth    int
	maxUnauth  int
	window     time.Duration
}

// unauthWindow is the period over which unauthorized chats get maxUnauth messages.
// Long enough to stop code guessing (32^8 codes), short enough that a mistyped code
// or re-authorizing after /reset doesn't lock the operator out until a restart.
const unauthWindow = 10 * time.Minute

type rateBucket struct {
	count     int
	windowStart time.Time
}

// NewState creates or loads auth state
func NewState(path string) (*State, error) {
	state := &State{
		path:        path,
		pendingAuth: make(map[string]time.Time),
	}

	// Try to load existing state
	if err := state.Load(); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("loading state: %w", err)
		}
		// File doesn't exist, will be created on first save
	}

	// Code will be generated when /start is called
	return state, nil
}

// Load loads state from disk
func (s *State) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, s)
}

// Save persists state to disk. Callers must not hold mu.
func (s *State) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.saveLocked()
}

// saveLocked writes state to disk. Caller must hold mu (read or write).
func (s *State) saveLocked() error {
	// Ensure directory exists
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating state directory: %w", err)
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling state: %w", err)
	}

	selfwatch.ExpectWrite(s.path)
	return atomicfile.WriteFile(s.path, data, 0600)
}

// IsAuthorized checks if a specific chat ID is authorized.
// Pass an empty string only if you want to check whether nobody is authorized.
func (s *State) IsAuthorized(chatID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.AuthorizedChat != "" && s.AuthorizedChat == chatID
}

// IsAnyoneAuthorized returns true if any chat has been authorized.
// Use this for decisions that apply to the whole notifier (startup/shutdown messages).
func (s *State) IsAnyoneAuthorized() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.AuthorizedChat != ""
}

// AuthorizedChatID returns the authorized chat ID, or "" if nobody is authorized
func (s *State) AuthorizedChatID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.AuthorizedChat
}

// Authorize marks a chat as authorized
func (s *State) Authorize(chatID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authorizeLocked(chatID)
}

// RedeemCode authorizes chatID if it sent /start and code is the current
// pairing code. The check and the authorization happen under one lock, so two
// chats racing with the same code can't both be told they paired.
func (s *State) RedeemCode(chatID, code string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, pending := s.pendingAuth[chatID]; !pending || !s.codeMatchesLocked(code) {
		return false, nil
	}
	return true, s.authorizeLocked(chatID)
}

// authorizeLocked marks a chat as authorized. Caller must hold mu.
func (s *State) authorizeLocked(chatID string) error {
	s.AuthorizedChat = chatID
	s.AuthorizedAt = time.Now()
	s.CodeUsed = true
	s.Code = "" // burn the code
	// Other chats that sent /start can't pair any more
	s.pendingAuth = make(map[string]time.Time)
	return s.saveLocked()
}

// GetCode returns the current auth code
func (s *State) GetCode() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Code
}

// VerifyCode checks if the provided code matches
func (s *State) VerifyCode(code string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.codeMatchesLocked(code)
}

// codeMatchesLocked reports whether code is the current, unused pairing code.
// Caller must hold mu.
func (s *State) codeMatchesLocked(code string) bool {
	// Already authorized
	if s.AuthorizedChat != "" {
		return false
	}

	// Code already used
	if s.CodeUsed {
		return false
	}

	return s.Code != "" && hmac.Equal([]byte(s.Code), []byte(code))
}

// MarkPendingAuth marks a chat as waiting for auth code (after /start)
func (s *State) MarkPendingAuth(chatID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pendingAuth[chatID] = time.Now()
}

// IsPendingAuth checks if a chat is waiting for auth code
func (s *State) IsPendingAuth(chatID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, pending := s.pendingAuth[chatID]
	return pending
}

// ClearPendingAuth removes a chat from pending auth list
func (s *State) ClearPendingAuth(chatID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pendingAuth, chatID)
}

// Deauthorize removes authorization from current chat
func (s *State) Deauthorize() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AuthorizedChat = ""
	s.AuthorizedAt = time.Time{}
	s.CodeUsed = false
	s.Code = "" // Clear code - will be generated on next /start
	return s.saveLocked()
}

// CodeForStart returns the auth code to pair with after /start: the current
// unused code if there is one, otherwise a new one. Reusing it means a stranger
// sending /start can't invalidate the code the operator is copying from the logs.
func (s *State) CodeForStart() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Code == "" || s.CodeUsed {
		s.Code = generateCode()
		s.CodeUsed = false
	}
	return s.Code
}

// generateCode creates a random auth code in FOG-XXXX-XXXX format
func generateCode() string {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no ambiguous chars
	buf := make([]byte, 8)
	// crypto/rand.Read never returns an error; it crashes the program rather
	// than hand out predictable bytes
	rand.Read(buf)

	code := make([]byte, 8)
	for i := 0; i < 8; i++ {
		code[i] = chars[int(buf[i])%len(chars)]
	}

	return fmt.Sprintf("FOG-%s-%s", code[:4], code[4:])
}

// Sanitize cleans inbound text input
func Sanitize(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if r > unicode.MaxASCII {
			return -1
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)

	if len(s) > 64 {
		s = s[:64]
	}

	return s
}

// ValidateCode checks if a string matches the auth code format
func ValidateCode(code string) bool {
	return codeRegex.MatchString(code)
}

// NewRateLimiter creates a rate limiter
func NewRateLimiter(maxAuth, maxUnauth int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		authorized: make(map[string]*rateBucket),
		unauth:     make(map[string]*rateBucket),
		maxAuth:    maxAuth,
		maxUnauth:  maxUnauth,
		window:     window,
	}
}

// CheckAuthorized checks if an authorized chat is within rate limits
func (rl *RateLimiter) CheckAuthorized(chatID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, exists := rl.authorized[chatID]
	if !exists {
		bucket = &rateBucket{
			count:       0,
			windowStart: time.Now(),
		}
		rl.authorized[chatID] = bucket
	}

	// Check if window expired
	if time.Since(bucket.windowStart) > rl.window {
		bucket.count = 0
		bucket.windowStart = time.Now()
	}

	bucket.count++
	return bucket.count <= rl.maxAuth
}

// CheckUnauthorized checks if an unauthorized chat should be responded to
func (rl *RateLimiter) CheckUnauthorized(chatID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Forget expired buckets so random chats can't grow the map forever
	for id, b := range rl.unauth {
		if now.Sub(b.windowStart) > unauthWindow {
			delete(rl.unauth, id)
		}
	}

	bucket, exists := rl.unauth[chatID]
	if !exists {
		bucket = &rateBucket{windowStart: now}
		rl.unauth[chatID] = bucket
	}

	bucket.count++
	return bucket.count <= rl.maxUnauth
}

// SignCallback generates an HMAC-signed callback token
func SignCallback(verb, noun, secret string) string {
	payload := fmt.Sprintf("%s:%s", verb, noun)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	signature := fmt.Sprintf("%x", mac.Sum(nil))
	return fmt.Sprintf("%s:%s", payload, signature[:16])
}

// VerifyCallback verifies an HMAC-signed callback token
func VerifyCallback(token, secret string) (verb, noun string, valid bool) {
	parts := strings.Split(token, ":")
	if len(parts) != 3 {
		return "", "", false
	}

	verb = parts[0]
	noun = parts[1]
	providedSig := parts[2]

	payload := fmt.Sprintf("%s:%s", verb, noun)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	expectedSig := fmt.Sprintf("%x", mac.Sum(nil))[:16]

	if !hmac.Equal([]byte(providedSig), []byte(expectedSig)) {
		return "", "", false
	}

	return verb, noun, true
}
