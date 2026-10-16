# service-health (410)

**DEADMAN.** Checks that a list of systemd services are running and alerts when
one stops.

## What it's for

Stopping security services is often the first thing an intruder does with
root: the firewall, AppArmor, the journal. It is also how you find out a
service you depend on has crashed. auditd has its own, more thorough check in
[auditd-health](../auditdhealth/README.md).

## How it works

Every `poll_interval` it runs `systemctl is-active <service>` for each service:

| Condition | Alert | Severity |
|---|---|---|
| Not `active` | [DEADMAN] Service Stopped | CONTACT |
| Back to `active` | [DEADMAN] Recovered: Service Stopped | NOMINAL |

Each service alerts once when it stops and once when it recovers. Any state
other than `active` (`inactive`, `failed`, `activating`, a unit that doesn't
exist) counts as stopped. The first check runs one `poll_interval` after
start.

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
| `watch_services` | `sshd systemd-journald` (code), `sshd auditd` (shipped YAML) | Unit names (`.service` optional) |

The shipped list is a starting point, not a recommendation: drop `sshd` if you
don't run an SSH server, and drop `auditd` if auditd-health is enabled.

## Examples

**Watch your defences.** Pick the services an attacker would want gone:

```yaml
config:
  watch_services:
    - apparmor
    - ufw
    - systemd-journald
    - unattended-upgrades
```

**Only list services that exist.** A service that isn't installed is never
`active`, so it alerts as stopped straight away. Check with
`systemctl is-active <name>` first.

**SSH on Debian and Ubuntu.** If you run an SSH server, its unit is `ssh`;
`sshd` is only an alias. From Ubuntu 22.10 sshd is socket activated:
`ssh.service` is inactive until someone connects, so watch `ssh.socket`
instead.

## Enabling

```bash
sudo fogbot skill enable service-health
```
