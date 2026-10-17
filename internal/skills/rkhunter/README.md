# rkhunter (600)

Reads rkhunter's log after each scan and alerts on warnings that weren't in the
previous scan, on every rootkit it finds, and on rkhunter not scanning at all.

## What it's for

rkhunter compares system binaries with the hashes it recorded when the system
was clean, and looks for the files, strings and processes of known rootkits.
A trojaned `/usr/bin/ssh` or `ps` shows up as "file properties have changed".
That is only useful if someone reads the result, and the result is a log in
`/var/log` or a mail to root that nobody reads. This puts it on your phone.

rkhunter warns about a lot of things that are fine. Unless you tune it, it
gives the same warnings every day, and people learn to ignore them. So this
skill only tells you about what changed since the last scan. Use the
[false positives](#avoiding-false-positives) section to quiet the rest.

## How it works

It reads `log_path` once a minute and picks out each rkhunter run, from
`Running Rootkit Hunter version` to `Info: End date is`. Runs that didn't do
the checks, such as `--update` and `--versioncheck`, are skipped. It handles
the log being added to (`--appendlog`, as Debian's cron job does), rewritten,
or rotated.

When a scan finishes, it compares the `Warning:` lines and their details with
the previous scan:

| Alert | Severity | When |
|---|---|---|
| rkhunter Warning | CONTACT | A warning that wasn't in the previous scan, or new detail lines under one that was (e.g. one more file in "Suspicious file types found in /dev"). Only the new lines are quoted |
| Possible Rootkit (rkhunter) | CONTACT | A warning that mentions a rootkit, or a scan with `Possible rootkits:` above 0. Sent after **every** scan that has it, not just the first |
| More rkhunter Findings | CONTACT | One scan had more than 5 findings to report: the rest go in one alert |
| [DEADMAN] rkhunter Not Scanning | CONTACT | No scan finished in `max_scan_age` |
| [DEADMAN] Recovered: rkhunter Not Scanning | NOMINAL | A scan finished again |

Activity is the warning, Equipment quotes up to five of its detail lines, and
Unit says whether it is new since the last scan. Text from the log is cleaned
before it goes into an alert, because rkhunter quotes file names that an
attacker can choose.

**At startup** it reads the whole log. The last scan in it becomes the
baseline: its warnings count as already known, so restarting fogbot doesn't
send them again. If that scan found a rootkit, it alerts. Read the log
yourself (`sudo grep Warning /var/log/rkhunter.log`) when you first enable the
skill, because the warnings already in it won't be sent.

**Not scanning** is treated as a finding. An attacker who turns rkhunter off
leaves nothing in its log, so if no scan finishes in `max_scan_age` (counted
from the last one in the log, or from fogbot starting), you get a DEADMAN
alert. [pkg-monitor](../pkgmonitor/README.md) will tell you if rkhunter is
removed.

The skill changes nothing on the system and needs no approval. It doesn't run
scans or updates itself: rkhunter's own cron jobs do that.

### Keeping the data files up to date

rkhunter's data files (known-bad program versions, backdoor ports, suspicious
strings, mirrors, translations) are updated by `rkhunter --update`. Leave that
to the system: Debian's package installs `/etc/cron.weekly/rkhunter`, which
runs it when `/etc/default/rkhunter` has:

```sh
CRON_DB_UPDATE="true"
```

Debian and Ubuntu also ship rkhunter with downloads turned off, so the weekly
job fails until you add this to `/etc/rkhunter.conf.local`:

```sh
# Debian sets WEB_CMD="/bin/false". Empty means rkhunter uses wget or curl,
# so one of them must be installed.
WEB_CMD=""
# Debian's MIRRORS_MODE=1 means "local mirrors only", and there are none
MIRRORS_MODE=0
UPDATE_MIRRORS=1
```

Check it works with `sudo rkhunter --update`: it exits 0 when there's nothing
new and 2 when it updated something. The weekly job mails root only if
something goes wrong (or always, with `DB_UPDATE_EMAIL="true"`), so check that
command by hand now and then.

Be realistic about how much this gets you. rkhunter's last release was 1.4.6,
in 2018, and its data files rarely change. Updating is cheap and gets you any
new data that does come out, but it won't teach rkhunter about recent
rootkits.

**Never automate `--propupd`.** `rkhunter --propupd` records the current
hashes of system binaries as known-good. Run on a schedule, it would also
record a trojaned binary as known-good, and rkhunter would never warn about
it. To handle package upgrades, use `PKGMGR` instead (below).

## Requirements

- rkhunter, scanning on a schedule. Debian's package installs
  `/etc/cron.daily/rkhunter` but leaves it off. Set `CRON_DAILY_RUN="true"` in
  `/etc/default/rkhunter`
- A file properties database: run `sudo rkhunter --propupd` once, on a system
  you trust, before the first scan
- Optionally, weekly data file updates, as above

## Configuration

Set in `/etc/fogbot/skills-available/600-rkhunter.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/600-rkhunter.yaml`).

```yaml
config:
  log_path: /var/log/rkhunter.log
  alert_on_warning: true
  alert_on_infection: true
  repeat_warnings: false
  max_scan_age: 48h
```

| Key | Default | Meaning |
|---|---|---|
| `log_path` | `/var/log/rkhunter.log` | rkhunter's log (its `LOGFILE`) |
| `alert_on_warning` | `true` | Alert on warnings |
| `alert_on_infection` | `true` | Alert on rootkits found |
| `repeat_warnings` | `false` | Alert on every warning in every scan, not just new ones |
| `max_scan_age` | `48h` | Alert if no scan finishes for this long. `off` to never |

The skill doesn't start if neither `/usr/bin/rkhunter` nor `log_path` exists.

## Avoiding false positives

Most rkhunter warnings on a working desktop come from a short list of causes.
Fix each one in rkhunter's config, not in fogbot. Then the scans really are
clean, and a new warning means something.

Put your changes in `/etc/rkhunter.conf.local`, or in a `*.conf` file in
`/etc/rkhunter.d/`, so package upgrades don't overwrite them. For a setting
that takes one value, the last file to set it wins. After editing:

```bash
sudo rkhunter -C                       # check the config parses
sudo rkhunter --check --sk --rwo       # scan now, print only warnings
```

Whitelist the **exact path** you've checked whenever you can, and use
wildcards only when names change, such as per-process files. Each entry is a
place rkhunter stops looking, and an attacker can hide there too.

| Warning | Cause | Setting |
|---|---|---|
| `The file properties have changed` for many files after `apt upgrade` | The upgrade changed the binaries rkhunter recorded | `PKGMGR=DPKG`: rkhunter checks package files against dpkg's own hashes, so upgraded files pass. See the caveats below |
| `No copy of the passwd file exists`, or every file "properties have changed" on the first scan | No file properties database yet | `sudo rkhunter --propupd` once, on a system you trust |
| `The command '/usr/bin/lwp-request' has been replaced by a script` (likewise `egrep`, `fgrep`, `which`, `ldd`, `adduser` on some releases) | Distributions now ship these as scripts | `SCRIPTWHITELIST=/usr/bin/lwp-request`, one line per command, after checking with `file` and `dpkg -S` that the script belongs to a package |
| `Hidden directory found: /etc/.java` / `/etc/.git` / `/dev/.lxc` | Java, etckeeper, LXC | `ALLOWHIDDENDIR=/etc/.java` |
| `Hidden file found: /etc/.gitignore` / `/etc/.etckeeper` / `/etc/.updated` / `/etc/.pwd.lock` | etckeeper, systemd, shadow-utils | `ALLOWHIDDENFILE=/etc/.updated` |
| `Suspicious file types found in /dev:` listing `/dev/shm/...` | Browsers, Electron apps, PulseAudio/PipeWire and PostgreSQL keep shared memory files there | `ALLOWDEVFILE=/dev/shm/.org.chromium.Chromium.*`, `ALLOWDEVFILE=/dev/shm/pulse-shm-*`, `ALLOWDEVFILE=/dev/shm/PostgreSQL.*`. Malware also drops files in `/dev/shm`, so allow the narrowest pattern that works |
| `The SSH and rkhunter configuration options should be the same` (`PermitRootLogin`) | rkhunter's `ALLOW_SSH_ROOT_USER` doesn't match `sshd_config` | `ALLOW_SSH_ROOT_USER=prohibit-password`, or whatever your `sshd_config` says. If it doesn't set `PermitRootLogin`, use `unset` |
| SSH `Protocol` warning | Modern OpenSSH has no `Protocol` option | `ALLOW_SSH_PROT_V1=2` (Debian's default) |
| `suspicious (large) shared memory segments` | Browsers, Xorg, PipeWire, VMs use large segments | `ALLOWIPCPROC=/usr/lib/firefox/firefox` per program, or raise `IPC_SEG_SIZE` |
| `Process '...' is listening on the network` / promiscuous interface | Only if you enabled `packet_cap_apps`/`promisc`: dhclient, NetworkManager, wireshark's dumpcap, libvirt | `ALLOWPROCLISTEN=/usr/bin/dumpcap`, `ALLOWPROMISCIF=virbr0` |
| `hidden ports`, `deleted files`, `hidden processes` | Debian disables these tests, which are noisy on desktops (`DISABLE_TESTS=suspscan hidden_ports hidden_procs deleted_files packet_cap_apps apps`) | Keep them disabled unless you're prepared to whitelist `PORT_WHITELIST` entries for your own services |
| `The operating system has changed` after a release upgrade | rkhunter recorded the old release | Check the upgrade went cleanly, then `sudo rkhunter --propupd` |

Things that aren't false positives, even though they're expected:

- **Changes to `passwd` and `group`.** You'll get one alert for the user or
  group you added. The next scan repeats the warning, so it isn't sent again.
- **A file you changed by hand**, such as a binary you rebuilt. Check it's
  yours, then run `sudo rkhunter --propupd /path/to/file` to record it.

**`PKGMGR=DPKG` caveats.** rkhunter then trusts dpkg's hash list
(`/var/lib/dpkg/info/*.md5sums`), which root can rewrite. An attacker who
replaces `/usr/bin/ssh` and also fixes its md5sums entry gets past rkhunter.
The trade is still usually worth it: without `PKGMGR`, every upgrade means
re-running `--propupd`, and in practice people run it without checking first.
Set `PKGMGR_NO_VRFY` for any package whose files you change on purpose.

**`APT_AUTOGEN="true"`** in `/etc/default/rkhunter` is the other common fix
for upgrades: it runs `--propupd` after every dpkg run. It records whatever is
on disk at that moment as known-good, including anything changed while apt
was running. Prefer `PKGMGR=DPKG`, and don't use both.

### Conditions that cause spurious alerts

- **Laptops on battery.** Debian's cron job skips the scan on battery
  (`RUN_CHECK_ON_BATTERY="false"`). A laptop that's never plugged in at
  cron.daily time stops scanning, and after `max_scan_age` you'll get a
  DEADMAN alert. Set `RUN_CHECK_ON_BATTERY="true"`, or raise `max_scan_age`.
- **Machines that sleep overnight.** cron.daily only runs if the machine is
  awake at its time, unless anacron is installed (Ubuntu desktops have it).
  Without anacron, a workstation that's off at 06:25 never scans.
- **Running `rkhunter --check` by hand.** Your scan goes into the log like any
  other, and fogbot reports what it adds. Its findings are compared with the
  previous scan, so a manual run with different options (say `--enable all`)
  shows up as new warnings, and the next daily scan doesn't repeat them.
- **Apt running during the scan.** Files change mid-scan. `PKGMGR=DPKG` mostly
  covers this, and [pkg-monitor](../pkgmonitor/README.md) tells you an upgrade
  was happening.

## Examples

**A machine that's only on some days**, such as a laptop: allow a long gap
before calling it a DEADMAN.

```yaml
  max_scan_age: 168h
```

**Get reminded until warnings are fixed.** If you want rkhunter's warnings
every day until you deal with them, as its mail does:

```yaml
  repeat_warnings: true
```

## Enabling

```bash
sudo fogbot skill enable rkhunter
```
