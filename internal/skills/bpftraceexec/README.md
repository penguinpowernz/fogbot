# bpftrace-exec (800)

> **Planned.** This skill has no code yet, so `fogbot skill enable` refuses it.
> This page describes the design.

Uses bpftrace to watch how programs are started: shells spawned by servers,
interpreters run with inline code, `curl | sh` style droppers, and `ptrace`
attaching to other processes.

## What it's for

A web server or database starting a shell is what a successful remote exploit
looks like from the inside. `python -c '...'` and `bash -c "$(curl ...)"` are
how payloads run without a file. `ptrace` is how one process injects code into
another. eBPF sees all of these in the kernel as they happen, with the parent
process, which polling `/proc` can miss.

For programs run from `/tmp`, `/dev/shm` or memfd, see
[proc-exec](../procexec/README.md); for shells holding network connections, see
[net-watch](../netwatch/README.md).

## How it will work

Runs a bpftrace program on the `execve` and `ptrace` tracepoints and alerts on
the configured parent/child pairs, interpreter `-c` flags, a downloader piping
into a shell, and `ptrace` attach calls. If bpftrace isn't installed the skill
does nothing.

## Requirements

- bpftrace
- root

## Configuration

Set in `/etc/fogbot/skills-available/800-bpftrace-exec.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/800-bpftrace-exec.yaml`).

```yaml
config:
  suspicious_parent_child:
    - parent: nginx
      child: [bash, sh, dash]
    - parent: apache2
      child: [bash, sh, dash]
    - parent: postgres
      child: [bash, sh, dash]
  alert_interpreter_c_flag: true
  alert_curl_pipe_sh: true
  alert_ptrace: true
```

| Key | Meaning |
|---|---|
| `suspicious_parent_child` | Parent process names and the children they must never start |
| `alert_interpreter_c_flag` | Alert on interpreters run with inline code (`-c`, `-e`) |
| `alert_curl_pipe_sh` | Alert on a downloader piped into a shell |
| `alert_ptrace` | Alert on `ptrace` attach |

## Examples

**Workstation services.** Servers on a workstation are things like a dev
database or the print service. None of them should start a shell:

```yaml
config:
  suspicious_parent_child:
    - parent: mysqld
      child: [bash, sh, dash]
    - parent: redis-server
      child: [bash, sh, dash]
    - parent: cupsd
      child: [bash, sh, dash]
```

Leave out parents that run shell commands by design, such as `node` (npm
scripts), `make` or your editor.

**Known false positives.** Running `gdb` or `strace` yourself uses ptrace and
will alert; if you debug often, set `alert_ptrace: false`. Build tools and
package scripts run `python3 -c` and `perl -e` routinely; if that is too noisy,
set `alert_interpreter_c_flag: false`.

## Enabling

Not yet available.
