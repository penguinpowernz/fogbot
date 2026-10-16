# kernel-mod (700)

> **Planned.** This skill has no code yet, so `fogbot skill enable` refuses it.
> This page describes the design.

Watches for kernel modules being loaded or unloaded, kernel security settings
being changed, and `LD_PRELOAD` hooking.

## What it's for

A kernel module runs with complete control of the machine, which is why
kernel rootkits arrive as one. Before going that far, attackers often weaken
the kernel's defences: turning off ASLR (`randomize_va_space`), relaxing ptrace
restrictions so they can attach to other processes, or the reverse, setting
`modules_disabled` after loading their own module so nothing else can be loaded
to find it.

## How it will work

Follows the kernel log for module load/unload messages, polls each of
`watch_sysctl_paths` for changes from their startup values, and checks
processes for an `LD_PRELOAD` environment variable. The system-wide
`/etc/ld.so.preload` file belongs to [fs-anomaly](../fsanomaly/README.md).

## Requirements

- root
- Access to the kernel log (`dmesg`)

## Configuration

Set in `/etc/fogbot/skills-available/700-kernel-mod.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/700-kernel-mod.yaml`).

```yaml
config:
  alert_module_load: true
  alert_module_unload: true
  alert_sysctl_change: true
  alert_ld_preload: true
  watch_sysctl_paths:
    - /proc/sys/kernel/randomize_va_space
    - /proc/sys/kernel/yama/ptrace_scope
    - /proc/sys/kernel/modules_disabled
```

| Key | Meaning |
|---|---|
| `alert_module_load` | Alert when a module loads |
| `alert_module_unload` | Alert when a module unloads |
| `alert_sysctl_change` | Alert when a watched sysctl changes |
| `alert_ld_preload` | Alert on processes running with `LD_PRELOAD` |
| `watch_sysctl_paths` | sysctls to watch, as `/proc/sys` paths |

## Examples

**More sysctls worth watching.** These rarely change on a running workstation
and each one loosens something an attacker cares about:

```yaml
config:
  watch_sysctl_paths:
    - /proc/sys/kernel/randomize_va_space
    - /proc/sys/kernel/yama/ptrace_scope
    - /proc/sys/kernel/modules_disabled
    - /proc/sys/kernel/kptr_restrict
    - /proc/sys/kernel/dmesg_restrict
    - /proc/sys/net/ipv4/ip_forward
```

`ip_forward` turning on, on a machine that doesn't route (no VMs, no VPN
gateway), suggests it is being set up as a pivot.

**Module loads on a laptop.** Plugging in USB devices loads modules, so expect
alerts then. A module load while the machine is idle and you're away is the one
to look at.

**`LD_PRELOAD` on a desktop.** Some programs set it legitimately (Steam,
overlays like MangoHud). Expect alerts from those; a preload from `/tmp`,
`/dev/shm` or a home directory is the one to look at.

## Enabling

Not yet available.
