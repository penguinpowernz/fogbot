# pkg-monitor (300)

Follows `/var/log/dpkg.log` and alerts when packages are installed, removed or
upgraded.

## What it's for

An attacker with root often installs tooling (`nmap`, `socat`, a compiler) or
removes whatever might catch them (`auditd`, `rkhunter`, fogbot itself). Both
leave a line in dpkg's log. On a machine where you are the only one who
installs software, an install you didn't do is a strong signal.

## How it works

It tails `log_path` from its current end (handling log rotation) and matches
dpkg's action lines:

| dpkg line | Alert | Severity |
|---|---|---|
| `install <pkg>:<arch> <none> <ver>` (fresh install) | Package Installed | MOVEMENT |
| `remove <pkg>:<arch> <ver>` | Package Removed | MOVEMENT |
| `upgrade <pkg>:<arch> <old> <new>` | Package Upgraded | MOVEMENT |

Each kind of alert is rate limited: after the first `dedup.max_burst` (default
10, set in `/etc/fogbot/config.yaml`) in a dedup window, the rest are held and
sent as one digest when the window ends, so a large `apt upgrade` arrives as
a handful of messages rather than hundreds.

It only sees dpkg. Software from snap, flatpak, pip or a binary copied into
place never shows up here.

## Requirements

- A Debian-family system writing `/var/log/dpkg.log`

## Configuration

Set in `/etc/fogbot/skills-available/300-pkg-monitor.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/300-pkg-monitor.yaml`).

```yaml
config:
  log_path: /var/log/dpkg.log
  alert_on_install: true
  alert_on_remove: true
  alert_on_upgrade: false
```

| Key | Default | Meaning |
|---|---|---|
| `log_path` | `/var/log/dpkg.log` | dpkg log to follow |
| `alert_on_install` | `true` | Alert on fresh installs |
| `alert_on_remove` | `true` | Alert on removals |
| `alert_on_upgrade` | `true` (code), `false` (shipped YAML) | Alert on upgrades |

## Examples

**Unattended upgrades.** With `unattended-upgrades` running, upgrades happen
on their own every day. Leave `alert_on_upgrade: false` (as shipped) so only
installs and removals reach you. Kernel updates still arrive as installs,
since each new kernel is a new `linux-image-*` package.

**Security tooling removed.** No extra config: a "Package Removed" for
`auditd`, `apparmor`, `ufw` or `fogbot` is worth dropping everything for. Pair
with [service-health](../servicehealth/README.md) to also catch the service
being stopped without the package being removed.

## Enabling

```bash
sudo fogbot skill enable pkg-monitor
```
