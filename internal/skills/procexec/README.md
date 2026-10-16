# proc-exec (210)

Alerts when a program runs from a staging directory such as `/tmp` or
`/dev/shm`, or from an in-memory file (fileless execution).

## What it's for

Installed software runs from `/usr`, `/opt` and the like. Droppers download
their payload into somewhere world-writable (`/tmp`, `/dev/shm`, `/run/user`)
and run it from there. More careful malware writes the payload into an
anonymous in-memory file (`memfd_create`) and executes that, so it never touches
the disk at all.

## How it works

It subscribes to the kernel's process events connector, so every `exec` is
checked as it happens, even for processes that live for a fraction of a second.
It also scans `/proc` every `poll_interval` as a backstop: that sees what was
already running when fogbot started, and anything whose event was missed.

For each process it reads `/proc/<pid>/exe`:

| Executable | Alert | Severity |
|---|---|---|
| Inside one of `suspicious_paths` | Suspicious Process Execution | CONTACT |
| `/memfd:...` (with `detect_memfd_exec`) | Fileless Process Execution | CONTACT |

The alert includes the PID, process name and full command line. Each process is
reported once.

## Requirements

- `/proc`
- root, for the process events connector (without it, polling only)

## Configuration

Set in `/etc/fogbot/skills-available/210-proc-exec.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/210-proc-exec.yaml`).

```yaml
config:
  poll_interval: 30s
  suspicious_paths:
    - /tmp
    - /dev/shm
    - /run
  check_process_hiding: true
  detect_memfd_exec: true
```

| Key | Default | Meaning |
|---|---|---|
| `poll_interval` | `5s` | Time between `/proc` scans |
| `suspicious_paths` | `/tmp /dev/shm /run/user` | Directories (and everything under them) to alert on |
| `detect_memfd_exec` | `true` | Alert on executables run from memfd |
| `check_process_hiding` | | Not implemented yet |

A path matches only on a directory boundary: `/tmp` matches `/tmp/x` and
`/tmp/a/b`, not `/tmpfiles/x`.

## Examples

**Add the other world-writable places.** `/var/tmp` survives reboots and is as
writable as `/tmp`; `/dev/mqueue` is an obscure tmpfs that tooling sometimes
abuses because nobody looks there:

```yaml
config:
  suspicious_paths:
    - /tmp
    - /var/tmp
    - /dev/shm
    - /dev/mqueue
    - /run
```

**Downloads folder.** Running a binary straight out of `~/Downloads` is how a
lot of workstation compromises start. If you never do that yourself, add it:

```yaml
    - /home/alice/Downloads
```

**Known false positives.** AppImages mount themselves under `/tmp/.mount_*` and
run from there, so each AppImage you start alerts. Some container runtimes
briefly re-exec themselves from memfd (`/memfd:runc_cloned...`) when starting a
container; set `detect_memfd_exec: false` on hosts that run containers if that
is too noisy.

## Enabling

```bash
sudo fogbot skill enable proc-exec
```
