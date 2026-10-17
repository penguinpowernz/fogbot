# suid-sweep (200)

Sweeps the filesystem for SUID/SGID files and alerts when one appears or
changes compared to a baseline you have approved.

## What it's for

A SUID binary runs as its owner, usually root, whoever starts it. Planting one
(or setting the bit on a copy of `bash`) is a classic way to keep root access
after getting it once. New SUID files outside package manager control are a
strong sign something is wrong.

## How it works

1. On startup, and every `sweep_interval` after that, it walks `watch_paths`
   and records every file with the SUID or SGID bit: path, owner, mode and
   SHA-256. A file over `max_hash_mb` isn't read: any user can set the SUID bit
   on a file of their own, and hashing a huge (or sparse) one would stall the
   sweep. Its size and mtime stand in for the hash, so a change to it is only
   seen if one of those changes. Set `alert_on_too_large: true` to get a CONTACT
   "SUID/SGID File Too Large to Hash" alert for each one.
2. With no approved baseline yet, the sweep is saved as a pending baseline and a
   NOMINAL "SUID Baseline Pending Approval" alert asks you to review it.
3. Once approved, each sweep is compared against the baseline. A new SUID/SGID
   file ("New SUID/SGID Binary Detected"), or a baselined one whose contents,
   mode or owner changed ("SUID/SGID Binary Modified"), raises a CONTACT alert,
   once per change. Removed files are not reported.
4. Accepting a change (e.g. after a package upgrade) is the same as the first
   approval:

```bash
sudo fogbot baseline diff      # see what changed
sudo fogbot baseline approve   # accept the current state
```

5. `no_suid_paths` are swept at the same time, but for places no SUID/SGID
   file belongs. Anything found there raises a CONTACT "SUID/SGID File in
   No-SUID Path" alert, with or without an approved baseline. These paths are
   kept out of the baseline (and skipped if they sit inside `watch_paths`), so
   approving it never clears the alert. It is reported once per file and
   contents, and again if it comes back after being removed or losing the bit.

## Requirements

- root, to read every directory being swept

## Configuration

Set in `/etc/fogbot/skills-available/200-suid-sweep.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/200-suid-sweep.yaml`).

```yaml
config:
  sweep_interval: 1h
  watch_paths:
    - /bin
    - /sbin
    - /usr/bin
    - /usr/sbin
    - /usr/local/bin
    - /usr/local/sbin
  no_suid_paths:
    - /home
    - /root
    - /tmp
    - /var/tmp
    - /dev/shm
  max_hash_mb: 200
  alert_on_too_large: false
```

| Key | Default | Meaning |
|---|---|---|
| `sweep_interval` | `1h` | Time between sweeps |
| `watch_paths` | `/usr /bin /sbin /opt /home` | Directories walked, recursively; symlinks are not followed |
| `no_suid_paths` | none (shipped: `/home /root /tmp /var/tmp /dev/shm`) | Directories where any SUID/SGID file alerts; `[]` switches this off |
| `max_hash_mb` | `200` | Largest file hashed, in MB; bigger ones are compared by size and mtime |
| `alert_on_too_large` | `false` | Alert (CONTACT) for each SUID/SGID file over `max_hash_mb` |

## Examples

**More places nothing should be SUID.** There is no legitimate reason for a
SUID file in a home directory, `/tmp` or `/var/tmp`, which is why the shipped
`no_suid_paths` cover them: they are exactly where an attacker would leave a
root shell. Add any other place you can write to without root, such as a
second data disk or where removable drives mount:

```yaml
config:
  sweep_interval: 15m
  watch_paths:
    - /usr
    - /bin
    - /sbin
    - /opt
  no_suid_paths:
    - /home
    - /root
    - /tmp
    - /var/tmp
    - /dev/shm
    - /mnt/data
    - /media
```

A large `/home` makes every sweep longer; lengthen `sweep_interval` if it shows.

**Faster detection.** A sweep only catches what exists when it runs. Shorten
`sweep_interval` to close the window, or pair this skill with
[dir-watch](../dirwatch/README.md) on `/usr/local/bin` to see the file being
written as it happens.

## Enabling

```bash
sudo fogbot skill enable suid-sweep
sudo fogbot baseline approve   # after reviewing the first sweep
```
