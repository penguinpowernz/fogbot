# Bug Fixes - Authentication & Command Handling

## Critical Bugs Found and Fixed

### 1. ❌ Command Handlers Were Stubs (CRITICAL)
**Issue:** All command handlers (`handleStart`, `handlePing`, `handleStatus`, `handleApprove`) had TODO comments and never sent responses back to users.

**Symptoms:**
- Bot receives `/start` but user gets no response
- Auth code sent but no confirmation
- `hi` command logs but no reply

**Root Cause:**
```go
// Before:
func handleStart(cmd notifier.Command, authState *auth.State) {
    log.Printf("Start command from %s, waiting for auth code", cmd.ChatID)
    // TODO: send "Enter authorization code" message  ← NEVER IMPLEMENTED!
    return
}
```

**Fix:**
- Added `notifier.Notifier` parameter to all handlers
- Added `telegram.SendText()` method for simple text responses
- Implemented actual response messages for all commands
- Added proper error handling

**Files Changed:**
- `cmd/fogbot/main.go` - All handler functions
- `internal/notifier/telegram/telegram.go` - Added `SendText()` method

---

### 2. ❌ Volume Mount Wiped System CA Certificates
**Issue:** Docker Compose mounted `./etc:/etc` which replaced the **entire** `/etc` directory, removing system files including CA certificates.

**Symptoms:**
```
Failed to send startup message: tls: failed to verify certificate:
x509: certificate signed by unknown authority
```

**Root Cause:**
```yaml
# Before:
volumes:
  - ./etc:/etc  ← Replaces ALL of /etc, including /etc/ssl/certs/
```

**Fix:**
```yaml
# After:
volumes:
  - ./etc/fogbot:/etc/fogbot  ← Only mount fogbot config
```

**Files Changed:**
- `docker-compose.yml` - Changed volume mount to be specific

---

### 3. ❌ Direct Auth Code Input Not Supported
**Issue:** Users could only authenticate via `/start FOG-CODE`. Typing just `FOG-CODE` was ignored.

**Symptoms:**
- User types `FOG-A3X9-K2M7` directly → No response
- Had to use `/start FOG-A3X9-K2M7` format

**Root Cause:**
Command parser lowercases input: `FOG-A3X9-K2M7` becomes verb `fog-a3x9-k2m7` which doesn't match `"start"`.

**Fix:**
Added fallback in default case to detect auth codes:
```go
default:
    // Check if this is an auth code sent directly (FOG-XXXX-XXXX)
    if !authState.IsAuthorized(cmd.ChatID) && auth.ValidateCode(strings.ToUpper(cmd.Verb)) {
        // Treat direct code input as "/start CODE"
        cmd.Args = []string{"start", strings.ToUpper(cmd.Verb)}
        cmd.Verb = "start"
        handleStart(ctx, cmd, authState, notif)
    }
}
```

**Files Changed:**
- `cmd/fogbot/main.go` - Added code detection in default case

---

### 4. ❌ TLS Configuration Missing
**Issue:** Go binary in Docker couldn't verify HTTPS certificates.

**Fixes Applied:**
1. **Dockerfile:** Added `update-ca-certificates` and environment variables
2. **Telegram client:** Added proper `tls.Config` with MinVersion TLS 1.2
3. **Added escape hatch:** `FOGBOT_INSECURE_TLS=true` for testing (not production!)

**Files Changed:**
- `Dockerfile` - CA cert updates and env vars
- `internal/notifier/telegram/telegram.go` - TLS configuration

---

## How to Test the Fixes

### Test Authentication Flow

1. **Start the daemon:**
```bash
docker-compose up -d
docker-compose logs -f
```

2. **Note the auth code:**
```
Authorization code: FOG-A3X9-K2M7
```

3. **In Telegram, try BOTH methods:**
```
Method 1: /start FOG-A3X9-K2M7
Method 2: FOG-A3X9-K2M7
```

Both should now work and respond with:
```
✅ Authorization successful!

You can now use fogbot commands:
• hi / hello - Test connection
• /status - View system status
```

4. **Test authorized commands:**
```
hi
hello
/status
```

Should get responses for each.

---

## Additional Improvements Made

### Better Error Messages
- Auth code format validation with helpful message
- TLS errors now suggest checking certificates
- Invalid codes show clear rejection

### User Experience
- Welcome message shows available commands
- Status includes "coming in Phase X" notes
- Emoji indicators for better visibility

### Development
- Added `TROUBLESHOOTING.md` with solutions
- Added `BUGFIXES.md` (this file)
- Updated error logging throughout

---

## Known Limitations (By Design)

1. **No Unix Socket Yet:** CLI talks directly to config files, not running daemon
2. **Simple Text Messages:** Using Alert structure for text (works but not ideal)
3. **No Uptime Tracking:** handlePing shows zero uptime (TODO)
4. **Stub Responses:** Status and approve show "coming in Phase X" messages

These are intentional - Phase 1/1.5 is about infrastructure, not full features.

---

## Testing Checklist

- [x] `/start` with code → Gets response
- [x] Direct code input → Gets response
- [x] Invalid code → Gets rejection message
- [x] Already authorized → Gets confirmation
- [x] `hi` command → Gets online status
- [x] `/status` → Gets status report
- [x] Telegram TLS works in Docker
- [x] CA certificates present in container
- [x] Rate limiting works (10/60s auth)
- [x] Unauthorized chats get 3 message budget

---

## Performance Notes

- Long polling timeout: 30 seconds (efficient)
- Poll interval: 1 second between checks (responsive)
- Rate limiting: In-memory, resets per window
- Auth state: Persists to `/var/lib/fogbot/state.json`

---

## Security Notes

✅ **Good:**
- Input sanitization on all inbound text
- Rate limiting prevents abuse
- HMAC-signed callback tokens
- TLS 1.2+ only
- Auth code is crypto/rand generated

⚠️ **TODO for Production:**
- Remove `FOGBOT_INSECURE_TLS` option
- Add command rate limiting per user
- Add audit logging for all auth attempts
- Consider TOTP instead of one-time codes
