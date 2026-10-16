# resource-anomaly (900)

> **Planned.** This skill has no code yet, so `fogbot skill enable` refuses it.
> This page describes the design.

Polls `/proc` for processes using unusual amounts of CPU, memory or disk I/O.

## What it's for

A crypto miner pins every core it can get, for hours. Exfiltration tools read
a lot of disk in a short time. Neither needs to touch any file or port the
other skills watch, but both show up as resource use.

## How it will work

Every `poll_interval` it samples per-process CPU, memory and I/O from `/proc`
and alerts on a process above `cpu_threshold_pct` for longer than
`cpu_sustained_seconds`, above `memory_threshold_mb`, or reading/writing faster
than `io_threshold_mb_per_sec`.

Hidden processes (a PID in `/proc` that `ps` doesn't show) are a rootkit sign,
not a resource one; that check is planned for
[proc-exec](../procexec/README.md).

## Requirements

- `/proc`

## Configuration

Set in `/etc/fogbot/skills-available/900-resource-anomaly.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/900-resource-anomaly.yaml`).

```yaml
config:
  poll_interval: 30s
  cpu_threshold_pct: 90
  cpu_sustained_seconds: 30
  memory_threshold_mb: 1024
  io_threshold_mb_per_sec: 50
```

| Key | Meaning |
|---|---|
| `poll_interval` | Time between samples |
| `cpu_threshold_pct` | CPU use that counts as high |
| `cpu_sustained_seconds` | How long CPU must stay high before alerting |
| `memory_threshold_mb` | Resident memory that alerts |
| `io_threshold_mb_per_sec` | Disk throughput that alerts |

## Examples

**Builds and browsers.** Compiling and video calls legitimately pin the CPU on
a workstation, and browsers and IDEs often hold more than 1 GB. A sustained
threshold of several minutes catches a miner, which never stops, without
alerting on every build; raise the memory threshold above what your usual apps
use:

```yaml
config:
  cpu_threshold_pct: 80
  cpu_sustained_seconds: 600
  memory_threshold_mb: 4096
```

## Enabling

Not yet available.
