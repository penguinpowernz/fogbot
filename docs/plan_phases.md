# fogbot: Phased Delivery Plan

Architectural decisions (interfaces, package structure, config format) are established in Phase 1 and not revisited. Later phases add sensors and features without touching core.

---

## Phase 1 — Core Infrastructure (skeleton only) ✅ COMPLETE
*Goal: project compiles and runs. All interfaces defined. No Telegram, no skills, no auth — just the skeleton everything else hangs off.*

- [x] Project scaffold — `go.mod`, package structure, `fogbot.service`
- [x] `/etc/fogbot/skills-available/` — directory created on install, ships with all prebuilt skill YAMLs (18 skills: 100-900)
- [x] `/etc/fogbot/skills-enabled/` — empty on install, operator populates with symlinks
- [x] `internal/config/` — YAML parsing, validation, defaults, SIGHUP reload, environment variable overrides
- [x] `internal/notifier/notifier.go` — `Notifier` interface, `Alert` and `Command` types, severity constants
- [x] `internal/skills/skill.go` — `Skill` interface + YAML schema (`id`, `name`, `description`, `why`, `requires`, `config`)
- [x] `internal/skills/loader.go` — read symlinks from `skills-enabled/`, parse YAMLs, build active skill set, smart filename matching
- [x] `internal/dedup/` — dedup and rate-limiting engine with configurable window and burst limits
- [x] `internal/dropin/dropin.go` — drop-in file writer (safe write, verify, remove) with dry-run mode support
- [x] `internal/dropin/ledger.go` — append-only change ledger with SHA256 checksums
- [x] `cmd/fogbot/main.go` — daemon entry point, signal handling, SIGHUP config reload
- [x] `cmd/fogbot/cli/` — cobra subcommands: `skill list|enable|disable|info`, `version`
- [x] `config.yaml.example` with comprehensive documentation
- [x] **BONUS:** Makefile with build, test, docker, and package targets
- [x] **BONUS:** Docker Compose test environment with proper capabilities
- [x] **BONUS:** Dry-run mode via `FOGBOT_DRY_RUN` environment variable
- [x] **BONUS:** Debian package structure (etc/, usr/, var/) ready for ian
- [x] **BONUS:** .gitignore, .dockerignore, .ianignore for proper artifact management

**Exit criteria:** ✅ All met. `go build` succeeds. `fogbot daemon` starts, reads `skills-enabled/`, exits cleanly on SIGTERM. `fogbot skill list` prints the available/enabled table with all 17 skills. Ledger records all operations.

**Implementation notes:**
- Unix socket for CLI↔daemon comms deferred to Phase 2 (CLI currently direct-to-config)
- Shell completion scaffold deferred (cobra supports it, needs hookup)
- Environment variables added for all paths (`FOGBOT_CONFIG`, `FOGBOT_STATE_DIR`, `FOGBOT_SKILLS_*`) for testing flexibility
- Smart skill name matching handles numeric prefixes (e.g., "ssh-monitor" matches "100-ssh-monitor.yaml")

---

## Phase 1.5 — Telegram Auth & Ping ✅ COMPLETE
*Goal: prove the Telegram plumbing works end to end. First human interaction with the bot.*

- [x] `internal/notifier/telegram/` — Telegram implementation, long polling, message sending, inline keyboard support, SALUTE-formatted alerts
- [x] `internal/auth/` — TOFU challenge-response, `state.json` persistence, `FOG-XXXX-XXXX` code generation, inbound rate limiting (10 auth/60s, 3 unauth lifetime), unauth chat_id budget
- [x] Improved auth flow — code generated only on `/start` (not on daemon startup), pending auth state tracking, code scanning in any message after `/start`
- [x] Command handlers — `/start` (generate code + mark pending), `/help` (context-aware), `/reset` (deauthorize), `hi`/`hello` (ping)
- [x] Input sanitization pipeline — applied to all inbound text without exception (ASCII only, control chars stripped, 64 char limit)
- [x] Signed callback token generation and verification (HMAC-SHA256 keyed on bot token)
- [x] Inline keyboard scaffolding (mechanism working, acknowledge buttons ready)

**Exit criteria:** ✅ All met. fogbot starts (no code generated), operator DMs `/start`, bot generates and logs code, operator pastes code in any message, bot confirms auth. Command handlers process `/start`, `/help`, `/reset`, `hi`, `hello`. Unauthorized chats are rate-limited and silently dropped.

**Implementation notes:**
- Alert formatting uses SALUTE structure (Size, Activity, Location, Unit, Time, Equipment)
- Emoji indicators: 🔴 CONTACT (red), 🟡 MOVEMENT (yellow), 🟢 NOMINAL (green)
- Rate limiter tracks both authorized (windowed) and unauthorized (lifetime budget) chats
- Callback verification prevents replay attacks on inline keyboard buttons
- Dry-run mode skips Telegram sends when `FOGBOT_DRY_RUN=true`
- Auth code generated on-demand via `/start`, not on daemon startup — improves security and reduces log noise
- Pending auth state allows flexible code input in any message after `/start`

---

## Phase 2 — First Skills (high value, low complexity)
*Goal: real detection using existing log files. No kernel instrumentation, no system config changes.*

- [ ] `internal/skills/100-ssh-monitor/` — parse `/var/log/auth.log`: SSH login success/fail, sudo, su, root direct login, brute force
- [ ] `internal/skills/210-proc-exec/` — `/proc` polling: executables in `/tmp`/`/dev/shm`, process hiding detection
- [ ] `internal/baseline/` — SUID sweep, `pending.json` state machine, Telegram approval flow with inline keyboard
- [ ] `internal/skills/200-suid-sweep/` — dual detection: auditd watches for chmod syscalls setting S_ISUID/S_ISGID (immediate, via `-k fogbot-200`), plus periodic sweep diffing filesystem state against approved baseline
- [ ] `internal/skills/300-pkg-monitor/` — tail `/var/log/dpkg.log`, alert on install/remove/upgrade events
- [ ] `internal/skills/400-log-freshness/` — [DEADMAN] inotify + ticker: alert if configured log files not written within N minutes
- [ ] `internal/skills/410-service-health/` — [DEADMAN] poll systemd via dbus: alert if configured services stop running
- [ ] `internal/skills/420-auditd-health/` — [DEADMAN] verify auditd process running + log is being written; alert on either going stale
- [ ] `fogbot skill list` — shows all registered skills with enabled/disabled status
- [ ] `fogbot skill enable/disable <skill>` — updates config.yaml, records in ledger, signals SIGHUP, notifies Telegram
- [ ] `fogbot skill info <skill>` — full detail view

**Exit criteria:** `fogbot skill list` shows all skills. Enable/disable works and Telegram is notified. fogbot detects SSH brute force, executables in `/tmp`, new dpkg installs, and a stopped service. Alerts print to stdout only — not yet Telegram.

---

## Phase 2.5 — Wire Skills to Telegram + Self-Watch
*Goal: alerts actually arrive on your phone — and fogbot immediately starts watching its own back.*

- [ ] Connect skill alert channel output to `Notifier.Send()` pipeline
- [ ] RED alert formatting — full SALUTE message, immediate send
- [ ] YELLOW alert formatting — rate-limited digest via dedup engine
- [ ] Alert acknowledge button — inline keyboard on each RED alert, signed callback token
- [ ] `internal/selfwatch/` — inotify on fogbot binary, `config.yaml`, `/var/lib/fogbot/` state dir, `changes.log`; whitelist own writes to avoid false positives
- [ ] End-to-end smoke test: trigger SSH brute force, receive 🔴 CONTACT on Telegram

**Exit criteria:** touching a watched file or triggering SSH failures produces a correctly formatted Telegram alert within seconds. Acknowledge button works. Unexpectedly modifying `config.yaml` or the fogbot binary from outside produces a 🔴 CONTACT alert.

---

## Phase 3 — Status Reports & Presence
*Goal: the daily/weekly heartbeat with interactive drill-down, plus continuous presence indication.*

- [ ] `internal/metrics/` — in-memory ring buffer accumulating per-section counts
- [ ] Scheduled report engine — timezone-aware ticker, catch-up report on restart
- [ ] Tier 1 summary message construction
- [ ] Tier 2 drill-down — inline keyboard per non-zero section, per-message-ID state, `[◀ Back]`
- [ ] `/status` command — on-demand report
- [ ] Quiet hours — suppress YELLOW during window, RED always fires
- [ ] **Startup / shutdown messages** — 🟢 NOMINAL messages to Telegram on daemon start and SIGTERM shutdown, include host label and version
- [ ] **Presence message system** — two-line status message (date + HH:MM) at bottom of chat
  - Update every 30 seconds via Telegram message edit
  - Store presence message ID in state.json
  - On restart: delete old presence message if exists, create new one
  - On normal alert send: delete and recreate presence message to keep it at bottom
  - Presence acts as continuous heartbeat without spamming notifications
- [ ] **Contact reports (anti-spam incident tracking)** — one alert per contact, prevents duplicate alerts
  - `internal/contacts/` — Contact report manager (create/update/close, check if open, auto-cleanup)
  - Storage in `/var/lib/fogbot/contacts/` as individual JSON files
  - Track start/end time, status (open/closed), SALUTE data, collected intel
  - Each skill implements `GatherIntel()` to define what intel to collect automatically
  - Update existing Telegram message when contact recurs (edit with new counts)
  - Optional resolution alerts when contact closes (configurable)
  - Status report integration showing open contacts count

**Exit criteria:** daily report arrives on schedule, operator drills into AUTH and FILES, `/status` returns immediate summary. Startup/shutdown messages sent on daemon lifecycle events. Presence message updates every 30s showing current time, stays at bottom of chat, and is recreated after each alert. Contact reports prevent alert spam — recurring anomalies update existing contact instead of sending new alert.

---

## Phase 4 — System-Level Skills (require system config / drop-ins)
*Goal: expand coverage using auditd and iptables. fogbot now writes drop-in configs and tracks them in the ledger.*

- [ ] `internal/skills/500-passwd-watch/` — auditd drop-in: watch `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, SSH config, PAM
- [ ] `internal/skills/510-port-tripwires/` — iptables drop-in: LOG rules for C2/malware ports inbound + outbound, `/proc/net/tcp` correlation
- [ ] `internal/skills/520-cron-watch/` — inotify: `/etc/cron*`, `/var/spool/cron`, `/etc/systemd/system/`, rc.local
- [ ] `internal/skills/530-fs-anomaly/` — inotify: hidden files/dirs, `/etc/ld.so.preload`, immutable flag, large staging files
- [ ] `internal/skills/600-rkhunter/` — tail `/var/log/rkhunter.log`, alert on WARNING/infection lines; graceful no-op if rkhunter not installed
- [ ] `internal/skills/610-chkrootkit/` — parse chkrootkit output log, alert on INFECTED/suspicious findings; graceful no-op if not installed
- [ ] `fogbot skill configure <skill>` — interactive prompts, writes config.yaml, records in ledger
- [ ] `fogbot changes` — pretty-print ledger, `--tail N`
- [ ] Extend selfwatch (Phase 2.5) to also cover active drop-in files as they are written

- [ ] Approval prompt at `fogbot skill enable` — show all commands to be run, require `[y/N]` before execution (default `autonomous: false`)
- [ ] `--autonomous` flag and `autonomous: true` config option to skip prompts
- [ ] Startup rule verification for all active system-config skills — query actual state, diff, re-apply missing rules, log to ledger, alert if anything was missing
- [ ] `/var/lib/fogbot/skills/<id>.state.json` — persist expected rule state per skill at enable time

**Exit criteria:** `fogbot skill enable 500-passwd-watch` shows commands and prompts for approval before writing drop-in. On next startup with the drop-in deleted, fogbot detects it missing, re-applies it, logs the repair, and sends a 🟡 MOVEMENT alert. rkhunter/chkrootkit skills parse logs if tools are present, skip cleanly if not. Self-watch automatically extends to cover new drop-in files as each skill is enabled.

---

## Phase 5 — Advanced Skills (kernel-level & hardware)
*Goal: deep visibility via bpftrace, kernel monitoring, and hardware events.*

- [ ] `internal/skills/800-bpftrace-exec/` — suspicious exec chains, interpreter `-c`, dropper patterns, ptrace; graceful degradation if bpftrace absent
- [ ] `internal/skills/700-kernel-mod/` — dmesg: module load/unload, `/proc/sys/kernel` changes, `LD_PRELOAD`, ASLR knob
- [ ] `internal/skills/900-resource-anomaly/` — CPU/mem/IO anomaly, crypto miner heuristics
- [ ] `internal/skills/710-net-watch/` — `ss`/`/proc/net/tcp`: unexpected outbound by process, suspicious correlations
- [ ] `internal/skills/715-net-discover/` — `fping` network sweep every 5min, baseline tracking, new IP alerts with Intel button
- [ ] `internal/skills/720-usb-monitor/` — USB device plug/unplug detection via udev events (primary) or lsusb polling (fallback)
  - Alert on new USB storage, keyboards, network adapters
  - Track vendor ID, product ID, serial number, device type
  - Configurable whitelist for expected devices (suppress alerts)
  - Intel button for device detail (lsusb -v output, kernel messages)

**Exit criteria:** fogbot detects shell spawned from nginx, kernel module load, sustained high CPU from unexpected process, new IP appearing on network, and USB device insertion/removal.

---

## Phase 6 — Intel System & Polish
*Goal: interactive reconnaissance, notifier portability, and operator education.*

- [ ] `internal/intel/` — Intel module interface + registry
- [ ] `internal/intel/net-scan/` — nmap, arp-scan, DNS lookups for new IPs
- [ ] `internal/intel/proc-detail/` — process tree, open files, memory maps for suspicious processes
- [ ] `internal/intel/file-analysis/` — hash, strings, file type, permissions history for suspicious files
- [ ] `internal/intel/port-intel/` — service ID, banner grab, reverse DNS for port tripwires
- [ ] `internal/intel/user-context/` — login history, sudo log for auth anomalies
- [ ] Telegram inline keyboard Intel buttons with HMAC-signed callbacks
- [ ] Intel result formatting and delivery via Telegram
- [ ] Map Intel modules to appropriate skill alerts
- [ ] `/why <id>` Telegram command — sends skill's `why:` field as explanation
- [ ] Additional notifier implementations (Slack, IRC — interface already defined in Phase 1)
- [ ] Structured JSON logging to journald for SIEM ingestion
- [ ] Threat intel IP blocklist integration (configurable feed URLs)
- [ ] DGA / high-entropy DNS detection
- [ ] Comprehensive test suite
- [ ] Installation script / Makefile
- [ ] `fogbot skill edit <id>` — open `$EDITOR` on skill YAML, reload daemon on save, notify Telegram of config change

---

## Out of Scope (initially)

- Automated response / active countermeasures (LP/OP doctrine: observe and report only)
- Web UI
- Multi-host aggregation
- SIEM integration (though structured JSON logs could feed one)
