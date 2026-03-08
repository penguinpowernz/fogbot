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
	unauth     map[string]int // lifetime message count for unauthed chats
	maxAuth    int
	maxUnauth  int
	window     time.Duration
}

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

// Save persists state to disk
func (s *State) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Ensure directory exists
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating state directory: %w", err)
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling state: %w", err)
	}

	return os.WriteFile(s.path, data, 0600)
}

// IsAuthorized checks if a chat ID is authorized
func (s *State) IsAuthorized(chatID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.AuthorizedChat == chatID
}

// Authorize marks a chat as authorized
func (s *State) Authorize(chatID string) error {
	s.mu.Lock()
	s.AuthorizedChat = chatID
	s.AuthorizedAt = time.Now()
	s.CodeUsed = true
	s.Code = "" // burn the code
	s.mu.Unlock()

	return s.Save()
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

	// Already authorized
	if s.AuthorizedChat != "" {
		return false
	}

	// Code already used
	if s.CodeUsed {
		return false
	}

	return s.Code == code
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
	s.AuthorizedChat = ""
	s.AuthorizedAt = time.Time{}
	s.CodeUsed = false
	s.Code = "" // Clear code - will be generated on next /start
	s.mu.Unlock()

	return s.Save()
}

// GenerateNewCode creates and stores a new auth code
func (s *State) GenerateNewCode() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Code = generateCode()
	s.CodeUsed = false
	return s.Code
}

// generateCode creates a random auth code in FOG-XXXX-XXXX format
func generateCode() string {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no ambiguous chars
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		panic(err) // crypto/rand failure is fatal
	}

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
		unauth:     make(map[string]int),
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

	count := rl.unauth[chatID]
	count++
	rl.unauth[chatID] = count

	return count <= rl.maxUnauth
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

	if providedSig != expectedSig {
		return "", "", false
	}

	return verb, noun, true
}
