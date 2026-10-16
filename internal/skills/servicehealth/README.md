# service-health (410)

**DEADMAN.** Checks that a list of systemd services are running and alerts when
one stops.

## What it's for

Security services stopping is often the first thing an intruder does with root:
the firewall, AppArmor, the audit daemon. It is also how you find out a service
you depend on has crashed.

## How it works

Every `poll_interval` it runs `systemctl is-active <service>` for each service:

| Condition | Alert | Severity |
|---|---|---|
| Not `active` | [DEADMAN] Service Stopped | CONTACT |
| Back to `active` | [DEADMAN] Recovered: Service Stopped | NOMINAL |

Each service alerts once when it stops and once when it recovers.

## Requirements

- systemd

## Configuration

Set in `/etc/fogbot/skills-available/410-service-health.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/410-service-health.yaml`).

```yaml
config:
  poll_interval: 60s
  watch_services:
    - sshd
    - auditd
```

| Key | Default | Meaning |
|---|---|---|
| `poll_interval` | `1m` | Time between checks |
| `watch_services` | `sshd systemd-journald` | Unit names (`.service` optional) |

## Examples

**Watch your defences.** Pick the services an attacker would want gone:

```yaml
config:
  watch_services:
    - auditd
    - apparmor
    - ufw
    - systemd-journald
    - unattended-upgrades
```

**Only list services that exist.** A service that isn't installed is never
`active`, so it alerts as stopped straight away. Check with
`systemctl is-active <name>` first.

**SSH on Debian and Ubuntu.** The SSH server's unit is `ssh`; `sshd` is only an
alias. From Ubuntu 22.10 sshd is socket activated: `ssh.service` is inactive
until someone connects, so watch `ssh.socket` instead.

## Enabling

```bash
sudo fogbot skill enable service-health
```
