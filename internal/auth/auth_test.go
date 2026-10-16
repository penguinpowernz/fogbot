package auth

import (
	"path/filepath"
	"testing"
	"time"
)

func TestCheckUnauthorized_BudgetResetsAfterWindow(t *testing.T) {
	rl := NewRateLimiter(10, 3, time.Minute)
	for i := 0; i < 3; i++ {
		if !rl.CheckUnauthorized("42") {
			t.Fatalf("message %d should be allowed", i+1)
		}
	}
	if rl.CheckUnauthorized("42") {
		t.Fatal("4th message should be over budget")
	}

	// Simulate the window passing
	rl.unauth["42"].windowStart = time.Now().Add(-unauthWindow - time.Second)
	if !rl.CheckUnauthorized("42") {
		t.Fatal("budget should reset after the window")
	}
}

func TestCheckUnauthorized_PerChat(t *testing.T) {
	rl := NewRateLimiter(10, 1, time.Minute)
	if !rl.CheckUnauthorized("1") || !rl.CheckUnauthorized("2") {
		t.Fatal("each chat gets its own budget")
	}
	if rl.CheckUnauthorized("1") {
		t.Fatal("chat 1 should be over budget")
	}
}

func TestAuthorizedChatID_SurvivesReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := NewState(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.AuthorizedChatID() != "" {
		t.Fatal("expected no authorized chat initially")
	}
	if err := s.Authorize("12345"); err != nil {
		t.Fatal(err)
	}

	reloaded, err := NewState(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.AuthorizedChatID(); got != "12345" {
		t.Fatalf("expected 12345 after reload, got %q", got)
	}

	if err := reloaded.Deauthorize(); err != nil {
		t.Fatal(err)
	}
	if reloaded.AuthorizedChatID() != "" || reloaded.IsAuthorized("") {
		t.Fatal("expected no authorized chat after Deauthorize")
	}
}

// A stranger's /start must not replace the code the operator is pairing with
func TestCodeForStart_ReusesUnusedCode(t *testing.T) {
	s, err := NewState(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	first := s.CodeForStart()
	if again := s.CodeForStart(); again != first {
		t.Fatalf("code changed from %s to %s", first, again)
	}

	s.MarkPendingAuth("other")
	if err := s.Authorize("operator"); err != nil {
		t.Fatal(err)
	}
	if s.IsPendingAuth("other") {
		t.Error("other chats should stop pending once a chat is authorized")
	}

	s.Deauthorize()
	if next := s.CodeForStart(); next == first {
		t.Error("a burned code was handed out again")
	}
}
