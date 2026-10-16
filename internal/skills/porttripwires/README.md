# port-tripwires (510)

Puts tripwires on TCP ports that nothing on your machine uses: any new
connection to one of them, in or out, raises an alert.

## What it's for

A workstation has a small, predictable set of ports in use. A connection
attempt to one it doesn't serve is somebody scanning or moving laterally; a
connection out to one it never talks to is often malware phoning home, a miner
reaching its pool, or a reverse shell to a Metasploit listener. The tripwire
doesn't block anything. It watches and reports.

## How it works

At enable time it builds `iptables` and `ip6tables` LOG rules from the port
lists and asks you to approve them before anything runs:

```
iptables -t raw -A PREROUTING ! -i lo -p tcp -m addrtype --dst-type LOCAL \
  -m multiport --dports 135,139,445,4444,31337,12345 \
  -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m limit --limit 1/sec --limit-burst 20 \
  -j LOG --log-prefix 'fw-510-in: '
```

- Rules go in the **raw** table, ahead of the filter table that ufw (or any
  other firewall manager) owns. They see traffic ufw drops as well as traffic
  it allows, and never change its verdicts or its rule order.
- Only the SYN that opens a connection is logged, rate limited, so an
  established session can't flood the kernel log.
- Inbound rules skip loopback and traffic routed through to VMs or containers.
- Outbound rules log the UID of the process that connected.
- IPv6 is covered too whenever the kernel has it: link-local addresses exist on
  every LAN interface even when your network doesn't hand out IPv6.

fogbot reads the hits from the kernel log (`/dev/kmsg`). Every hit is CONTACT:

| Direction | Alert |
|---|---|
| in | Inbound Connection to Tripwire Port (source address and port) |
| out | Outbound Connection to Tripwire Port (destination and the local user) |

A retrying client sends several SYNs, so after alerting a tripwire stays quiet
for `alert_cooldown` for the same remote address and port.

If the rules go missing, fogbot puts the approved ones back: quietly at
startup (after a reboot), alerting only if it can't, and with a System Config
Restored alert if they vanish while it's running (someone ran `iptables -F`).
After changing the port lists, run
`sudo fogbot skill enable port-tripwires` again to approve the new rules:
fogbot never runs one you haven't seen.

## Requirements

- iptables (and ip6tables)
- root
- Approval at enable time (it runs `iptables`)

## Configuration

Set in `/etc/fogbot/skills-available/510-port-tripwires.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/510-port-tripwires.yaml`).

```yaml
config:
  watch_inbound: [135, 139, 445, 4444, 31337, 12345]
  watch_outbound: [4444, 1080, 25, 3333, 5555, 7777, 14444]
  alert_cooldown: 5m
```

| Key | Default | Meaning |
|---|---|---|
| `watch_inbound` | | TCP ports to alert on connections *to* this machine (at most 15) |
| `watch_outbound` | | TCP ports to alert on connections *from* this machine (at most 15) |
| `alert_cooldown` | `5m` | Quiet period per remote address and port after an alert |

Only list ports nothing legitimate uses, or every legitimate connection alerts.

## Examples

**An SSH tripwire on a box that doesn't run sshd.** This is how to watch SSH
on a workstation you never log in to remotely: leave sshd off (or uninstalled)
and put a tripwire on 22. Nothing legitimate will ever connect, so any SYN is
someone on your LAN looking for a way in, and there's no SSH server for them to
attack:

```yaml
config:
  watch_inbound: [22]
```

If sshd does run because you need it, leave 22 out (every login would alert)
and use [ssh-monitor](../sshmonitor/README.md) instead. Don't start sshd just
to have something to watch.

**An RDP tripwire on a box that doesn't run RDP.** Port 3389 is one of the
most scanned ports there is, and worms and ransomware operators go looking for
it inside networks. If you don't run an RDP server, nothing should ever connect
to 3389 on your machine, so a single SYN means something on your LAN is
scanning for it:

```yaml
config:
  watch_inbound: [3389]
```

**A wider inbound net.** Remote-access and database ports you don't serve make
good tripwires for lateral movement:

```yaml
config:
  watch_inbound:
    - 22     # SSH (only if sshd isn't running)
    - 23     # telnet
    - 135    # MS RPC
    - 139    # NetBIOS
    - 445    # SMB
    - 1433   # MS SQL
    - 3389   # RDP
    - 5900   # VNC
    - 5985   # WinRM
    - 4444   # Metasploit default
```

Skip any you actually serve (445 if you share files with Samba, for instance).

**Outbound C2 and miners.** Ports an infected workstation tends to reach out
on and a normal one doesn't:

```yaml
config:
  watch_outbound:
    - 4444   # Metasploit / reverse shells
    - 6667   # IRC botnet C2
    - 3333   # Stratum mining pools
    - 14444  # Monero pools
    - 9001   # Tor relays
    - 23     # telnet (Mirai-style spreading)
    - 25     # direct-to-MX spam; mail clients use 587/465
```

## Enabling

```bash
sudo fogbot skill enable port-tripwires   # shows the iptables rules for approval
```
