# ssh-monitor (100)

Watches authentication events for SSH brute forcing, logins from addresses
never seen before, direct root logins, and failed `sudo`/`su` attempts.

## What it's for

SSH is the usual way in to a Linux box. Failed logins on their own mean little,
but a successful login from an address that has never connected before, a root
login that skips the `sudo` audit trail, or someone guessing at the `sudo`
password on a single-user workstation are all worth knowing about straight away.

## How it works

By default it follows the systemd journal (`journalctl -f`) and only believes a
message when the journal shows it really came from `sshd` (running as root),
`sudo` or `su`. Any local user can write fake lines into `/var/log/auth.log`
with `logger(1)`, so reading the file instead (`log_source: file`) is weaker and
fogbot logs a warning when it does.

| Event | Alert | Severity |
|---|---|---|
| Accepted login as `root` | Direct Root Login | CONTACT |
| Accepted login from an IP not seen since fogbot started | SSH Login from New IP | CONTACT |
| `brute_force_threshold` failures from one IP inside `brute_force_window` | SSH Brute Force | MOVEMENT |
| Wrong `sudo` password | Failed Sudo Attempt | MOVEMENT |
| `su` authentication failure | Failed su Attempt | MOVEMENT |

Successful `sudo` commands are logged by fogbot but not alerted on.

## Requirements

- Read access to the systemd journal (fogbot runs as root, so this is a given)
- Or, with `log_source: file`, a syslog daemon writing `auth.log`

## Configuration

Set in `/etc/fogbot/skills-available/100-ssh-monitor.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/100-ssh-monitor.yaml`).

```yaml
config:
  brute_force_threshold: 5
  brute_force_window: 60s
  alert_new_ip_login: true
  quiet_hours_exempt: false
  log_source: journal
  # auth_log_path: /var/log/auth.log
```

| Key | Default | Meaning |
|---|---|---|
| `brute_force_threshold` | `5` | Failed logins from one IP that make a brute force alert |
| `brute_force_window` | `60s` | Time window the failures are counted over |
| `alert_new_ip_login` | `true` | Alert on a successful login from an IP not seen before |
| `quiet_hours_exempt` | `false` | Reserved for quiet-hours handling; not used yet |
| `log_source` | `journal` | `journal`, or `file` to read `auth_log_path` |
| `auth_log_path` | `/var/log/auth.log` | File to read with `log_source: file`. Setting it on its own switches to `file` |

## Examples

**A workstation that never takes inbound SSH.** If nobody should ever log in
over SSH, then any accepted login is the alert. Leave `sshd` running (or don't
install it and skip this example) and keep `alert_new_ip_login: true`: the first
login from anywhere is a new IP.

**Tighter brute force detection.** The default only trips on a fast,
noisy guesser. A slow one spreading guesses out is caught with a wider window:

```yaml
config:
  brute_force_threshold: 3
  brute_force_window: 10m
```

**Failed sudo as an early warning.** On a single-user machine you are the only
person who types the `sudo` password. A Failed Sudo Attempt you didn't cause
means someone with a shell as you is trying to get root. No config needed: it
is always on.

## Enabling

```bash
sudo fogbot skill enable ssh-monitor
```
