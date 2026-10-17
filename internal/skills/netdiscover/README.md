# net-discover (715)

Listens for the hosts on the local network, keeps a baseline of them, and
alerts when a new one appears. It sends no traffic of its own.

## What it's for

A device joining your network that you didn't add could be a rogue access
point, a drop box someone plugged in, or a neighbour on your Wi-Fi. Knowing
what's normally on the network makes the new arrival stand out.

## How it works

It learns hosts from two passive sources on `interfaces`:

- the kernel's IPv4 and IPv6 neighbour table (as `ip neigh` shows it, read over
  netlink) every `poll_interval`: every host this machine has talked to;
- with `listen_broadcasts`, the ARP and DHCP broadcasts every host sends when it
  joins or looks for another, read from a raw socket (not promiscuous, and
  filtered in the kernel to ARP and DHCP requests). This catches hosts that
  never talk to this one, as soon as they join.

Hosts are tracked by MAC address, since DHCP moves IPs around. Each network
gets its own baseline, keyed by the gateway's MAC, so a laptop carried to a
café isn't compared against home:

- On a network with no approved baseline, it only learns, and says so once
  with a NOMINAL alert. Approve it while you're on it with
  `sudo fogbot baseline approve`.
- On an approved network, a MAC not in the baseline raises a CONTACT alert with
  its IP, MAC vendor, the hostname it gave DHCP and its reverse DNS name where
  available. The host is added to the pending baseline; approve it with
  `sudo fogbot baseline approve` if you expected it.

`sudo fogbot baseline diff` lists the hosts awaiting approval on each network.
Approval covers exactly the hosts it showed you: one that joins while the
prompt is open stays pending. The daemon and the CLI lock the baseline files
while changing them, so neither writes back a stale copy over the other.

A device that copies the MAC of an approved host is not noticed: tracking
hosts by MAC can't tell them apart.

**Gateway spoofing.** Because networks are keyed by the gateway's MAC, a
machine that ARP-spoofs the gateway (the usual way to get in the middle of
your traffic) would otherwise make your home network look like a new one and
put the skill into learning mode. So when the gateway MAC names no approved
network, but an approved network had the same gateway IP and this looks like
it (the old gateway's MAC is still present, the new gateway MAC is one of its
hosts, or two of its hosts are present, in the neighbour table or heard
broadcasting in the last 10 minutes), the interface stays on
that network's baseline and a CONTACT alert reports the change. If you
replaced the router, `sudo fogbot baseline approve` accepts the new MAC as
another gateway for that network. A café that happens to use the same
addressing as home shares none of its hosts, and is learned as a new network.

**Floods.** Anyone on the LAN can send ARP and DHCP from forged MACs. More
than 32 new hosts on an approved network in one `poll_interval` are reported
as one MAC flood alert, and the rest of them are neither alerted on nor added
to the pending baseline until an interval passes with fewer. The skill
remembers at most 4096 hosts per run and keeps at most 1024 pending per
network.

If the broadcast listener stops because the interface went down (Wi-Fi
reconnecting, resume from suspend) it is restarted on the next poll, backing
off up to an hour if it keeps failing. Without permission for the raw socket
it is not retried.

| Alert | Severity | When |
|---|---|---|
| Network Baseline Pending Approval | NOMINAL | first host seen on a network with no approved baseline (once per network while the daemon runs) |
| New Host on Network | CONTACT | a MAC not in the network's approved baseline (once per host while the daemon runs) |
| Gateway MAC Changed | CONTACT | the gateway IP of an approved network answers from a MAC not approved for it (once per MAC while the daemon runs) |
| MAC Flood on Network | CONTACT | over 32 new hosts in one poll interval, or 4096 in one run |

Baselines live in the state directory as `net_baseline.json` (approved) and
`net_baseline.pending.json`, keyed by the gateway's MAC. An interface listed in
`interfaces` with no default route has one baseline of its own (`if:<name>`).
Until the gateway's MAC is in the neighbour table the network is unknown and
nothing on it is recorded.

MAC vendors come from the IEEE OUI list of the `ieee-data` (or `hwdata`)
package; without it alerts have no vendor. Locally administered MACs show as
"randomised MAC".

An Intel button that runs nmap and arp-scan against the new host is planned,
and would be the only thing in this skill that sends traffic, only when you tap
it. It is not implemented yet.

## Requirements

- root (CAP_NET_RAW), for the raw socket (`listen_broadcasts`); reading the
  neighbour table alone needs none. If the socket can't be opened the daemon
  logs why and carries on with the neighbour table.
- optionally the `ieee-data` package, for MAC vendors

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

```bash
sudo fogbot skill enable 715
```

It changes nothing on the system, so there is nothing to approve. Then, on your
own network, review and approve what it has learned:

```bash
sudo fogbot baseline diff
sudo fogbot baseline approve
```
