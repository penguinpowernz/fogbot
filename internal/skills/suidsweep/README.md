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
   SHA-256.
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

## Requirements

- root, to read every directory being swept

## Configuration

Set in `/etc/fogbot/skills-available/200-suid-sweep.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/200-suid-sweep.yaml`).

```yaml
config:
  sweep_interval: 1h
  baseline_file: /var/lib/fogbot/suid_baseline.json
  watch_paths:
    - /bin
    - /sbin
    - /usr/bin
    - /usr/sbin
    - /usr/local/bin
    - /usr/local/sbin
```

| Key | Default | Meaning |
|---|---|---|
| `sweep_interval` | `1h` | Time between sweeps |
| `watch_paths` | the six bin/sbin dirs above | Directories walked recursively; symlinks are not followed. If the key is missing, `/usr /bin /sbin /opt /home` |
| `baseline_file` | | Not used: baselines live in fogbot's state dir (`/var/lib/fogbot`) |

## Examples

**Sweep the places nothing should be SUID.** There is no legitimate reason for
a SUID file in a home directory, `/tmp` or `/var/tmp`. Those are exactly where
an attacker would leave a root shell. Only SUID/SGID files are hashed, so the
cost is the directory walk; lengthen the interval if `/home` is very large:

```yaml
config:
  sweep_interval: 15m
  watch_paths:
    - /usr
    - /bin
    - /sbin
    - /opt
    - /home
    - /root
    - /tmp
    - /var/tmp
    - /dev/shm
```

**Faster detection.** A sweep only catches what exists when it runs. Shorten
`sweep_interval` to close the window, or pair this skill with
[dir-watch](../dirwatch/README.md) on `/usr/local/bin` to see the file being
written as it happens.

## Enabling

```bash
sudo fogbot skill enable suid-sweep
sudo fogbot baseline approve   # after reviewing the first sweep
```
