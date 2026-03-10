# fogbot: Security & Authentication

## Command Interface Security

### Design Principles
- **Prefer structured input** — Telegram inline keyboards mean the operator clicks a button. fogbot receives a fixed callback token, never free text. No parsing surface, nothing to sanitize.
- **Commands are a closed enum** — handler is a `switch` on known verbs. Anything not in the switch is silently dropped. No dynamic dispatch.
- **No shell, ever** — nothing in the command handler touches `exec.Command`. Sensors configure system tools at startup only. The command interface flips internal state only.
- **Log everything inbound** — every message received, from any chat_id, authorised or not, logged to journald. Full audit trail.

### Command Surface (intentionally minimal)

| Input | Method | Free text? | Notes |
|-------|--------|------------|-------|
| Auth code | Free text | **Yes** | Only free text accepted. Validated against `^FOG-[A-Z0-9]{4}-[A-Z0-9]{4}$` exact match. Reject anything else with no explanation. |
| Approve SUID baseline | Inline keyboard | No | Button only, signed callback token |
| Acknowledge alert | Inline keyboard | No | Button only, signed callback token |
| `/status` | Telegram command | No | Args silently dropped |

That is the entire interface. There is no command that accepts meaningful free-text operator input beyond the one-time auth code.

### Callback Token Signing
Telegram inline keyboard callbacks are strings fogbot generates itself:
```
verb:noun:hmac
e.g. approve:baseline:a3f9c2...
```
HMAC keyed on the bot token. If verification fails → drop silently, log the attempt. Prevents replay or mutation of callback tokens by anyone who intercepts them.

### Input Sanitization (defence in depth)
Even though structured input is preferred, all inbound text goes through a sanitization pipeline before touching any internal logic:

```go
// Applied to ALL inbound text without exception
func sanitize(s string) string {
    s = strings.TrimSpace(s)
    s = strings.Map(func(r rune) rune {
        if r > unicode.MaxASCII { return -1 }   // drop non-ASCII
        if unicode.IsControl(r) { return -1 }    // drop control chars
        return r
    }, s)
    if len(s) > 64 { s = s[:64] }               // hard length cap
    return s
}
```

After sanitization, auth code input is validated against the exact regex and nothing else. Any mismatch → drop, log, no response.

### Rate Limiting (inbound)
- Max 10 commands per 60s from the authorised chat
- Exceed threshold → fogbot stops responding until window clears
- Unauth chat_ids: max 3 messages lifetime before permanently ignored (prevents probing)

---

## Authentication (TOFU Challenge-Response)

Proves the operator has shell access before the bot will talk to anyone.

### Flow

```
1. fogbot starts
2. No auth code generated yet (waits for /start)
3. Bot ignores all unauthorized messages except /start, /help
4. /start → bot generates code: FOG-A3X9-K2M7
         → logs to stdout/journald: "*** AUTH CODE: FOG-A3X9-K2M7 ***"
         → marks chat as pending authorization
         → replies "Enter authorisation code"
5. Operator reads code from logs, pastes it in any message
6. Bot scans all messages from pending chats for valid codes
7. Code matches → chat_id saved to /var/lib/fogbot/state.json
                → chat_id also logged so operator can hardcode in config
                → code burned, never valid again
                → pending auth cleared
                → bot begins normal operation
8. /reset from authorized chat → deauthorize, clear code
9. Next /start generates fresh code
10. On restart: if state.json has an authorised chat_id, skip challenge entirely
```

### Properties

- **No expiry** — code valid until used, operator can take their time
- **First to auth wins** — subsequent auth attempts silently dropped
- **One authorised chat only** — no ambiguity about who the operator is
- **Code format**: `FOG-XXXX-XXXX` (crypto/rand, uppercase alphanum)
- **Code generation**: Only on `/start` command, not on daemon startup or reset
- **Additional commands**: `/help` (context-aware), `/reset` (deauthorize current chat)

### State Persistence

```json
{
  "authorized_chat_id": 123456789,
  "pending_auth_chat_ids": [987654321],
  "auth_code": "FOG-A3X9-K2M7",
  "auth_code_created_at": "2024-01-15T03:40:00Z"
}
```

Stored in `/var/lib/fogbot/state.json`. On restart, if `authorized_chat_id` is present, skip challenge entirely and resume normal operation.
