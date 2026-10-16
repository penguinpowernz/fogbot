# net-discover (715)

> **Planned.** This skill has no code yet, so `fogbot skill enable` refuses it.
> This page describes the design.

Sweeps the local network with `fping`, keeps a baseline of the hosts on it,
and alerts when a new one appears.

## What it's for

A device joining your network that you didn't add could be a rogue access
point, a drop box someone plugged in, or a neighbour on your Wi-Fi. Knowing
what's normally on the network makes the new arrival stand out.

## How it will work

Every `scan_interval` it pings every address in `networks` (skipping this
host's own and `exclude_ips`). The first sweep becomes a pending baseline for
you to approve; after that, any host not in the baseline raises an alert with
its MAC vendor and reverse DNS name where available.

The alert also carries an Intel button that runs nmap and arp-scan against the
new host. That only happens when you tap it.

Unlike fogbot's other skills, this one sends traffic: a ping to every address
in `networks` each sweep. Anything watching the LAN will see your workstation
doing a ping sweep every `scan_interval`.

## Requirements

- fping
- root

## Configuration

Set in `/etc/fogbot/skills-available/715-net-discover.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/715-net-discover.yaml`).

```yaml
config:
  scan_interval: 5m
  networks:
    - 192.168.1.0/24
  exclude_ips: []
  baseline_file: /var/lib/fogbot/net_baseline.json
  baseline_approval_required: true
  fping_timeout: 500ms
  fping_retries: 2
  include_mac_lookup: true
  include_reverse_dns: true
```

| Key | Meaning |
|---|---|
| `scan_interval` | Time between sweeps |
| `networks` | CIDR ranges to sweep |
| `exclude_ips` | Addresses to skip (this host's own are added automatically) |
| `baseline_file` | Where the known-hosts baseline is kept |
| `baseline_approval_required` | Require approval of the first sweep before alerting |
| `fping_timeout` / `fping_retries` | Per-host ping timeout and retries |
| `include_mac_lookup` | Add the MAC vendor to alerts |
| `include_reverse_dns` | Add the reverse DNS name to alerts |

## Examples

**Sweep only your own LAN.** List just the segment this workstation sits on,
and only if you run it, such as home or a lab. Don't add wider ranges or other
people's networks. A laptop that roams will sweep whatever network it is on
when that network uses the same range, such as office or hotel Wi-Fi on
192.168.1.0/24. Leave this skill off on laptops like that.

**Guest networks and DHCP churn.** Phones and laptops coming and going will
alert on a busy network. Point `networks` at a segment whose membership
should be stable, not the guest Wi-Fi.

## Enabling

Not yet available.
