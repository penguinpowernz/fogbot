# Skills

Each skill is one detection sensor, with its own directory here holding its
implementation and a README that explains what it detects, why it matters, how
to configure it, and examples:

```
internal/skills/<skill>/
├── README.md          # what it detects, why, its config, and examples
├── <skill>.go         # the implementation (absent for planned skills)
└── *_test.go
```

The skill's definition and default config ship as
`usr/share/fogbot/contrib/skills-available/<id>-<name>.yaml`, installed to
`/etc/fogbot/skills-available/`. `layout_test.go` checks every shipped skill has
a README here.

The files in this directory itself are the framework shared by all skills: the
`Skill` interface, the loader, the approval enabler and helpers.

## Available skills

| ID | Skill | Detects | Status |
|---|---|---|---|
| 100 | [ssh-monitor](sshmonitor/README.md) | SSH brute force, new-IP and root logins, failed sudo/su | ✅ |
| 200 | [suid-sweep](suidsweep/README.md) | New or modified SUID/SGID binaries | ✅ |
| 210 | [proc-exec](procexec/README.md) | Programs run from /tmp, /dev/shm or memory | ✅ |
| 300 | [pkg-monitor](pkgmonitor/README.md) | Package installs, removals, upgrades | ✅ |
| 400 | [log-freshness](logfreshness/README.md) | DEADMAN: logs going silent | ✅ |
| 410 | [service-health](servicehealth/README.md) | DEADMAN: services stopping | ✅ |
| 420 | [auditd-health](auditdhealth/README.md) | DEADMAN: auditd stopping or not logging | ✅ |
| 500 | [file-watch](filewatch/README.md) | Access to sensitive and canary files (auditd) | ✅ |
| 510 | [port-tripwires](porttripwires/README.md) | Connections to tripwire ports (iptables) | ✅ |
| 520 | [cron-watch](cronwatch/README.md) | New cron and at jobs | planned |
| 530 | [fs-anomaly](fsanomaly/README.md) | ld.so.preload, hidden files, immutable flags | planned |
| 540 | [dir-watch](dirwatch/README.md) | New files in watched directories (auditd) | ✅ |
| 550 | [systemd-watch](systemdwatch/README.md) | systemd reloads and unit file changes | ✅ |
| 600 | [rkhunter](rkhunter/README.md) | rkhunter findings | planned |
| 610 | [chkrootkit](chkrootkit/README.md) | chkrootkit findings | planned |
| 700 | [kernel-mod](kernelmod/README.md) | Kernel module loads, security sysctl changes, LD_PRELOAD | planned |
| 710 | [net-watch](netwatch/README.md) | Shells on the network, new listeners | planned |
| 715 | [net-discover](netdiscover/README.md) | New hosts on the LAN | planned |
| 800 | [bpftrace-exec](bpftraceexec/README.md) | Servers spawning shells, inline code, ptrace | planned |
| 900 | [resource-anomaly](resourceanomaly/README.md) | Miners and bulk I/O | planned |

## Tripwires and canaries

Several skills work best pointed at things you *don't* use, because then any
activity at all is the signal:

- [port-tripwires](porttripwires/README.md): watch port 3389 even if you don't
  run RDP. Nothing should ever connect to it. Likewise port 22 on a machine
  without sshd: don't run sshd just to have something to watch.
- [file-watch](filewatch/README.md): plant `~/.aws/credentials` even if you
  don't use AWS. Nothing legitimate will ever read it.
- [file-watch](filewatch/README.md): a decoy `~/.ssh/id_rsa` when your real key
  is `id_ed25519`.
- [service-health](servicehealth/README.md) and
  [pkg-monitor](pkgmonitor/README.md): a security tool being stopped or removed.

## Adding a skill

See [docs/adding-new-skill.md](../../docs/adding-new-skill.md).
