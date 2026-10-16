# net-watch (710)

> **Planned.** This skill has no code yet, so `fogbot skill enable` refuses it.
> This page describes the design. For connections in or out on specific ports,
> [port-tripwires](../porttripwires/README.md) works today.

Looks at open network connections, ties each to its process, and alerts on
shells and interpreters talking to the network, new listening ports, and
connections to blocklisted addresses.

## What it's for

`bash` with a TCP connection is a reverse shell. `python3` connected out to an
address you've never heard of might be a script you wrote, or might be a C2
beacon. A new port listening on all interfaces is a backdoor until shown
otherwise. These show up in the socket table whatever port they use, which is
what [port-tripwires](../porttripwires/README.md) can't see.

## How it will work

Every `poll_interval` it reads the socket table (`/proc/net/tcp*`), maps each
socket to its process through `/proc/<pid>/fd`, and alerts on:

- an established connection owned by one of `suspicious_processes`
- a listening socket that wasn't there before (`alert_new_listeners`)
- any connection to an address in `blocklist_ips`

## Requirements

- `/proc/net`
- root, to map sockets to other users' processes

## Configuration

Set in `/etc/fogbot/skills-available/710-net-watch.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/710-net-watch.yaml`).

```yaml
config:
  poll_interval: 30s
  suspicious_processes:
    - bash
    - sh
    - python
    - python3
    - perl
    - ruby
  alert_new_listeners: true
  blocklist_ips: []
```

| Key | Meaning |
|---|---|
| `poll_interval` | Time between socket table reads |
| `suspicious_processes` | Process names that shouldn't hold network connections |
| `alert_new_listeners` | Alert when a new listening port appears |
| `blocklist_ips` | Addresses any connection to which alerts |

## Examples

**Developer workstations.** If you run Python or Node scripts that talk to the
network, drop those interpreters from `suspicious_processes` and keep the
shells, adding `dash` and `zsh` to the default `bash` and `sh`: a shell with a
socket is never your normal workflow.

## Enabling

Not yet available.
