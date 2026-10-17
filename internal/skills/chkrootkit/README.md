# chkrootkit (610)

Reads chkrootkit's output after each daily scan and alerts on warnings that
weren't in the previous scan, on every `INFECTED` result, and on chkrootkit
not scanning at all.

## What it's for

chkrootkit uses different checks from [rkhunter](../rkhunter/README.md), so
running both catches more. It looks for the files and strings that known
rootkits and Linux malware leave, trojaned system commands, hidden processes,
packet sniffers, and executables in `/tmp`.

Like rkhunter, it warns about plenty that's fine, and it warns again in every
scan. So this skill only tells you about what changed since the last scan.
Use the [false positives](#avoiding-false-positives) section to quiet the
rest.

## How it works

Debian's `chkrootkit.timer` (or `/etc/cron.daily/chkrootkit` without systemd)
runs `chkrootkit-daily` once a day. That writes chkrootkit's full output to
`/var/log/chkrootkit/log.today`, after passing it through your `FILTER` and
`IGNORE_FILE`. The skill checks that file once a minute. When it has changed,
and chkrootkit has finished (no `chkrootkit` or `chkrootkit-daily` process is
running as root and the file hasn't changed for 30 seconds), it reads it.

Each check's output (from `Checking `sniffer'...` or `Searching for
Linux.Xor.DDoS...` up to the next check) is a finding if it says `INFECTED`,
`WARNING`, `Vulnerable`, `Possible`, `suspicious` or `hidden`, or if it has
lines that a check finding nothing doesn't print (anything but `not found`,
`not infected`, `nothing detected` and the like). The second rule is there
because chkrootkit prints file names as they are: anyone can create a file in
`/tmp` whose name contains a newline and a fake `Checking ... not infected`
line, which would otherwise hide the file names after it. Its lines are
compared with the previous scan:

| Alert | Severity | When |
|---|---|---|
| chkrootkit Warning | CONTACT | A check that warned and didn't in the previous scan, or new lines in one that did (a new file in `/tmp`, a new sniffer). Only the new lines are quoted |
| Possible Rootkit (chkrootkit) | CONTACT | A check said `INFECTED`. Sent after **every** scan that has it, not just the first |
| More chkrootkit Findings | CONTACT | One scan had more than 5 findings to report: the rest go in one alert |
| [DEADMAN] chkrootkit Not Scanning | CONTACT | No scan finished in `max_scan_age` |
| [DEADMAN] Recovered: chkrootkit Not Scanning | NOMINAL | A scan finished again |

Activity is the check's name, and Equipment quotes up to five of its new
lines. Two kinds of line are dropped because they say nothing about the
system: `RTNETLINK answers: ...` errors from the tools chkrootkit runs, and
`<iface>: not promisc and no packet sniffer sockets` (an interface the sniffer
check found clean). Text from the log is cleaned before it goes into an
alert, because chkrootkit quotes file names that an attacker can choose.

**At startup** it reads `log.today`, and that scan becomes the baseline: its
warnings count as already known, so restarting fogbot doesn't send them again.
If it has an `INFECTED` result, that is sent. Read the file yourself when you
first enable the skill, because the warnings already in it won't be sent.

**Not scanning** is treated as a finding. If no scan finishes in
`max_scan_age` (counted from `log.today`'s time, or from fogbot starting),
you get a DEADMAN alert. Disabling the timer, setting `RUN_DAILY="false"` or
removing the package all end the scans. Of those,
[systemd-watch](../systemdwatch/README.md) reports the timer being disabled and
[pkg-monitor](../pkgmonitor/README.md) the package being removed as they
happen.

### Signature updates

chkrootkit has no signature database to update: its checks are written into
the `chkrootkit` script and its helper programs. New checks only arrive with a
new package version, so keep it up to date the way you do other packages
(unattended-upgrades, or your usual `apt upgrade`). rkhunter, by contrast,
has data files of its own: see
[keeping them up to date](../rkhunter/README.md#keeping-the-data-files-up-to-date).

## Requirements

- chkrootkit, with Debian's daily job: `RUN_DAILY="true"` in
  `/etc/chkrootkit/chkrootkit.conf` (the default in current packages), and on
  systemd `systemctl enable --now chkrootkit.timer`
- Older packages read `/etc/chkrootkit.conf` and default to
  `RUN_DAILY="false"`

## Configuration

Set in `/etc/fogbot/skills-available/610-chkrootkit.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/610-chkrootkit.yaml`).

```yaml
config:
  log_path: /var/log/chkrootkit/log.today
  alert_on_infected: true
  alert_on_suspicious: true
  repeat_warnings: false
  max_scan_age: 48h
```

| Key | Default | Meaning |
|---|---|---|
| `log_path` | `/var/log/chkrootkit/log.today` | Where chkrootkit-daily writes the filtered output (its `OUTPUT`) |
| `alert_on_infected` | `true` | Alert on `INFECTED` results |
| `alert_on_suspicious` | `true` | Alert on warnings: suspicious files, sniffers, hidden processes, possible malware |
| `repeat_warnings` | `false` | Alert on every warning in every scan, not just new ones |
| `max_scan_age` | `48h` | Alert if no scan finishes for this long. `off` to never |

The skill doesn't start if the directory holding `log_path` doesn't exist.

## Avoiding false positives

chkrootkit's own notes on this are in
`/usr/share/doc/chkrootkit/README.FALSE-POSITIVES.gz`. Read them first.

chkrootkit-daily gives you three ways to quiet a finding, all set in
`/etc/chkrootkit/chkrootkit.conf`:

- **`IGNORE_FILE`** (`/etc/chkrootkit/chkrootkit.ignore`): extended regexps,
  one per line. Any output line matching one is dropped. This is the simplest
  and the one to reach for first, but it applies to **every** check's output,
  so anchor each pattern to just the line you mean.
- **`FILTER`**: a shell command the output is piped through, for rewriting
  lines that change every run (PIDs, interface names) into a stable form. The
  default already does this for network managers and `chkutmp` PIDs.
- **`RUN_DAILY_OPTS`**: options for chkrootkit itself. `-e '/path1 /path2'`
  excludes exact paths from the suspicious-files and known-rootkit-files
  checks, `-s 'regexp'` drops matching sniffer results, and `-n` / `-T
  fstype` skip NFS or other mounts.

fogbot reads `log.today`, which is the output after these filters, so
whatever you quiet there doesn't reach fogbot either. Check a pattern before
relying on it:

```bash
sudo grep -Ev -f /etc/chkrootkit/chkrootkit.ignore /var/log/chkrootkit/log.today.raw | less
```

Note that the `WARNING: ...` heading line stays even when you've filtered out
every path under it. That's fine: fogbot reports the heading once, then it's
the same every scan.

| Finding | Cause | Fix |
|---|---|---|
| `Searching for suspicious files and dirs... WARNING` listing hundreds of `/usr/lib/.../.gitignore`, `.github`, `.document`, `node_modules/.bin` | chkrootkit flags every dotfile under `/usr/lib`, and packages ship plenty (Ruby gems, Python and Node vendored libraries, Electron apps, `libc6-dbg`'s `/usr/lib/debug/.build-id`). Upgrades with versions in the path (`/usr/lib/dotnet/shared/.../8.0.31/.version`) make new lines every time | `IGNORE_FILE` patterns for the trees you've checked, e.g. `^/usr/lib/debug/\.(build-id\|dwz)$`, `^/usr/lib/google-cloud-sdk/`, `/node_modules/\.bin$`, `/\.(gitignore\|gitattributes\|github\|travis\.yml\|coveragerc\|readthedocs\.ya?ml\|pre-commit-config\.yaml)$`. For a few fixed paths, `RUN_DAILY_OPTS="-e '/usr/lib/debug/.dwz'"` is narrower |
| `Searching for Linux.Xor.DDoS... WARNING` listing files in `/tmp` | The check flags **any** executable file in `/tmp`. Compilers (`/tmp/go-build*/`), `apt source`, installers, and test runs leave them. On a development machine, this changes every day | Point build tools elsewhere, e.g. `export GOTMPDIR=$HOME/.cache/go-tmp` or `TMPDIR=$XDG_RUNTIME_DIR`, so `/tmp` stays clean and the check stays useful. Failing that, an `IGNORE_FILE` pattern for the one tool, e.g. `^/tmp/go-build[0-9]+/`. Don't ignore `^/tmp/` wholesale: dropping a binary in `/tmp` is exactly what Xor.DDoS and many other droppers do |
| `Searching for Linux BPF Door... WARNING` with `/proc/NNN/stack:... unix_seqpacket_recvmsg` | The check greps every process's kernel stack for `packet_recvmsg`, which also matches `unix_seqpacket_recvmsg`, an ordinary Unix socket wait | `IGNORE_FILE`: `^/proc/[0-9]+/stack:.*\bunix_seqpacket_recvmsg\b`. A real hit says `packet_recvmsg` on its own |
| `Checking 'sniffer'... WARNING` with `PACKET SNIFFER(...)` | Anything with a raw packet socket counts: dhclient, NetworkManager, wpa_supplicant, systemd-networkd (normalised by the default `FILTER`), and also wireshark's dumpcap, tcpdump, libvirt and VPN clients, whose PIDs change every run | `RUN_DAILY_OPTS="-s 'dumpcap\|tcpdump'"` for the ones you run, or extend `FILTER` to replace their PIDs. Leave anything you don't recognise: a sniffer is a classic implant |
| `Checking 'chkutmp'...` listing processes whose tty isn't in utmp | tmux and screen panes aren't recorded in utmp | Mostly normalised by the default `FILTER` (the PIDs become `{PID}`), so fogbot reports it only when a new program shows up. Running scans when you're detached helps |
| `Checking 'lkm'... You have N process hidden` | A process that exited between chkrootkit's `ps` and its `/proc` listing | Rare with Debian's patched `chkproc`. If it persists across scans, investigate: a hidden process is what an LKM rootkit does |
| `Checking 'bindshell'... WARNING` with `Potential bindshell installed: infected ports: 465` | Something legitimate is listening on a port a known backdoor uses (465 is SMTPS, 4369 is Erlang's epmd, 6667 is IRC, ...) | Find it with `sudo ss -lntup 'sport = :465'`. If it's yours, `IGNORE_FILE`: `^WARNING: Potential bindshell installed: infected ports: 465$` (the whole line, so another port still shows) |
| `Checking 'ls'... INFECTED`, or any other command | chkrootkit found a known trojan's strings in a system command. Rarely a packaging oddity | Treat it as real until shown otherwise: compare with `dpkg -V` / `debsums` and the package from another machine. Only then whitelist that exact line. fogbot sends `INFECTED` after every scan until it's gone |
| `RTNETLINK answers: Invalid argument` in many checks | `netstat`/`ip` errors on some kernels | Nothing to do: fogbot ignores these lines |

### Conditions that cause spurious alerts

- **Machines that aren't on every day.** `chkrootkit.timer` runs 30 minutes
  after boot and then every 24 hours the machine is up, and the cron.daily
  version needs the machine awake at cron.daily time (or anacron). A machine
  that's off for days triggers a DEADMAN alert after `max_scan_age`, so raise
  it on machines that aren't on every day.
- **Builds and installs running during the scan** put executables in `/tmp`
  (Xor.DDoS above) and new hidden files in `/usr/lib`.
- **Your own sessions.** tmux/screen sessions and packet captures you have
  open when the scan runs show up in `chkutmp` and `sniffer`.
- **`-q` in `RUN_DAILY_OPTS`.** It works, but chkrootkit then prints no check
  names, so fogbot groups all findings under one "chkrootkit" check and the
  alerts lose that context. Leave it out: fogbot already skips the clean
  results.
- **`DIFF_MODE`** affects only chkrootkit-daily's mail, not `log.today`, so
  it makes no difference to fogbot.

## Examples

**A development workstation.** Keep the Xor.DDoS check useful by keeping
build output out of `/tmp`, and ignore the vendored dotfiles you've checked:

```sh
# ~/.profile
export GOTMPDIR="$HOME/.cache/go-tmp"
```

```
# /etc/chkrootkit/chkrootkit.ignore
^/usr/lib/debug/\.(build-id|dwz)$
/node_modules/\.bin$
/\.(gitignore|gitattributes|github|travis\.yml|coveragerc)$
^/proc/[0-9]+/stack:.*\bunix_seqpacket_recvmsg\b
```

**A machine that's only on some days:**

```yaml
  max_scan_age: 168h
```

**Get reminded until warnings are fixed**, as chkrootkit-daily's mail does
with `DIFF_MODE="false"`:

```yaml
  repeat_warnings: true
```

## Enabling

```bash
sudo fogbot skill enable chkrootkit
```
