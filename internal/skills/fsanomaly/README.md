# fs-anomaly (530)

> **Planned.** This skill has no code yet, so `fogbot skill enable` refuses it.
> This page describes the design.

Looks for filesystem tricks attackers use: hidden files in staging areas,
`/etc/ld.so.preload` hooks, immutable flags, and large files piling up before
exfiltration.

## What it's for

- **`/etc/ld.so.preload`** makes every dynamically linked program load a
  library first. It is the standard way userland rootkits hide files and
  processes. On most systems the file doesn't exist at all.
- **Hidden files** (`.name`) in `/tmp`, `/dev/shm` and `/run` are how droppers
  try to avoid a casual `ls`.
- **The immutable flag** (`chattr +i`) stops even root deleting a file, so
  malware sets it on its own files to survive cleanup.
- **Large files in `/tmp`** are often an archive of your data waiting to be
  sent out.

Programs run from these directories are [proc-exec](../procexec/README.md)'s
job; the `LD_PRELOAD` environment variable is
[kernel-mod](../kernelmod/README.md)'s.

## How it will work

inotify on `watch_paths`; alerts on hidden file creation, the creation of or
any write to `/etc/ld.so.preload` (watched via `/etc`, since inotify can't
watch a file that doesn't exist yet), files gaining the immutable attribute,
and files larger than `large_file_threshold_mb`. Only files under
`watch_paths` are checked.

Desktop software also makes hidden files in `/tmp` (Chromium's
`.org.chromium.Chromium.*`, for one), so the design needs an ignore list
before `alert_hidden_files` is quiet enough for a workstation.

## Requirements

- inotify
- root

## Configuration

Set in `/etc/fogbot/skills-available/530-fs-anomaly.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/530-fs-anomaly.yaml`).

```yaml
config:
  watch_paths:
    - /tmp
    - /dev/shm
    - /run
    - /etc/ld.so.preload
  alert_hidden_files: true
  alert_immutable_flag: true
  large_file_threshold_mb: 100
```

| Key | Meaning |
|---|---|
| `watch_paths` | Directories and files to watch |
| `alert_hidden_files` | Alert on new dot-files in watched directories |
| `alert_immutable_flag` | Alert when a file gains `chattr +i` |
| `large_file_threshold_mb` | Size above which a new file alerts |

## Examples

**`ld.so.preload` as a tripwire.** If the file doesn't exist on your system
(check with `ls /etc/ld.so.preload`), its creation is almost certainly a
rootkit installing itself; the rare legitimate users, such as the Snoopy
command logger, are things you'd know you installed. Keep it in `watch_paths`
regardless.

## Enabling

Not yet available.
