# net-discover (715)

> **Planned.** This skill has no code yet, so `fogbot skill enable` refuses it.
> This page describes the design.

Listens for the hosts on the local network, keeps a baseline of them, and
alerts when a new one appears. It sends no traffic of its own.

## What it's for

A device joining your network that you didn't add could be a rogue access
point, a drop box someone plugged in, or a neighbour on your Wi-Fi. Knowing
what's normally on the network makes the new arrival stand out.

## How it will work

It learns hosts from two passive sources on `interfaces`:

- the kernel's neighbour table (`/proc/net/arp`, and the IPv6 neighbours), read
  every `poll_interval`: every host this machine has talked to;
- with `listen_broadcasts`, the ARP and DHCP broadcasts every host sends when it
  joins or looks for another, read from a raw socket (not promiscuous). This
  catches hosts that never talk to this one.

Hosts are tracked by MAC address, since DHCP moves IPs around. Each network
gets its own baseline, keyed by the gateway's MAC, so a laptop carried to a
café isn't compared against home:

- On a network with no approved baseline, it only learns. Approve it while
  you're on it with `sudo fogbot baseline approve`.
- On an approved network, a MAC not in the baseline raises a CONTACT alert with
  its IP, MAC vendor and reverse DNS name where available.

The alert has an Intel button that runs nmap and arp-scan against the new host.
That is the only thing in this skill that sends traffic, and only when you tap
it.

## Requirements

- root, for the raw socket (`listen_broadcasts`); reading the neighbour table
  alone needs none

## Configuration

Set in `/etc/fogbot/skills-available/715-net-discover.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/715-net-discover.yaml`).

```yaml
config:
  interfaces: []
  poll_interval: 1m
  listen_broadcasts: true
  exclude_macs: []
  include_mac_vendor: true
  include_reverse_dns: true
```

| Key | Meaning |
|---|---|
| `interfaces` | Interfaces to listen on; empty means the one with the default route |
| `poll_interval` | Time between reads of the neighbour table |
| `listen_broadcasts` | Also read ARP and DHCP broadcasts, to see hosts that never talk to this one |
| `exclude_macs` | MAC addresses never to alert on |
| `include_mac_vendor` | Add the MAC vendor (from a local OUI list) to alerts |
| `include_reverse_dns` | Add the reverse DNS name to alerts |

## Examples

**Leave VM and container bridges out.** Guests on `virbr0` or `docker0` come
and go with every VM you start. The default (the default-route interface)
already skips them; if you list `interfaces` yourself, list only the physical
LAN.

**Phones with private MAC addresses.** Phones use a random MAC per Wi-Fi
network, normally stable for that network, so each alerts once and is then
approved. A phone set to change its MAC regularly will keep alerting; add its
current MAC to `exclude_macs`, or accept that it shows up as new.

## Enabling

Not yet available.
