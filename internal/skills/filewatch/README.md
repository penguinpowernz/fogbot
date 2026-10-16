# file-watch (500)

Uses auditd to watch sensitive files and alerts on access, with the user and
program that touched them. Also the place to set **canary files**: decoys that
nothing legitimate ever opens.

## What it's for

`/etc/passwd`, `/etc/shadow` and `/etc/sudoers` control who gets in and who
gets root, so changes to them matter. Credential files matter for a different
reason: the first thing an intruder (or an infostealer) does is look for keys to
move further. A read of `~/.aws/credentials` by something other than the AWS
CLI is a very clear signal.

## How it works

At enable time it turns `watch_paths` into one auditd rule per path and asks
you to approve them before anything runs:

```
auditctl -w /etc/shadow -p rwa -k fb-file-500
```

Events tagged `fb-file-500` are read from the audit log and turned into a
"Critical File Access" alert naming the file, the operation, the UID, PID and
executable. Severity follows `severity_default` (`red`, so CONTACT), except that
anything under `/etc/shadow` or `/etc/sudoers` is always CONTACT.

auditd rules don't survive a reboot, so fogbot re-applies the approved ones at
startup. After changing `watch_paths`, run `sudo fogbot skill enable file-watch`
again to approve the new rules.

A path whose directory doesn't exist can't be watched and is skipped with a
log line; create the directory and enable again. A path that doesn't exist
itself is fine: auditd watches it and alerts when it is created. `fogbot skill
enable` prints the `touch` commands to create missing canaries.

## Requirements

- auditd
- root
- Approval at enable time (it runs `auditctl`)

## Configuration

Set in `/etc/fogbot/skills-available/500-file-watch.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/500-file-watch.yaml`).

`watch_paths` maps each path to the access that should alert:

| Flag | Alerts on |
|---|---|
| `r` | reads |
| `w` | writes |
| `a` | attribute changes (chmod, chown, xattrs) |
| `x` | executions |

```yaml
config:
  watch_paths:
    # Auth files - watch everything including reads (reads = recon)
    /etc/passwd: rwa
    /etc/shadow: rwa
    /etc/sudoers: rwa
    /etc/sudoers.d: rwa

    # SSH/PAM configs - writes and attribute changes only (reads are common)
    /etc/ssh/sshd_config: wa
    /etc/pam.d: wa

    # Canary files - watch everything, any access is suspicious
    /root/.ssh/id_rsa: rwxa
    /root/.ssh/authorized_keys: rwa
    /root/.aws/credentials: rwa
    /root/.kube/config: rwa
    /root/.netrc: rwa
    /root/.gnupg: rwa
    /root/.bitcoin/wallet.dat: rwa
    /root/.bash_history: rwa
```

Watching a directory covers everything beneath it.

The `r` on the auth files is loud: any program that maps a UID to a name
(`ls -l`, `ps`) reads `/etc/passwd`, and every `sudo` reads `/etc/shadow` and
`/etc/sudoers`. The default `/root/.bash_history` entry fires whenever root's
shell exits. Expect those alerts, or drop them to `wa`.

## Examples

**An AWS credentials canary, even if you don't use AWS.** Infostealers and
post-exploitation scripts grab `~/.aws/credentials` on sight. If you've never
used AWS, nothing legitimate on your machine will ever open that file, so any
read at all is an intruder looking for keys. Give it plausible contents so it
looks worth stealing (this is AWS's documented example key; it grants nothing):

```bash
mkdir -p ~/.aws
cat > ~/.aws/credentials <<'EOF'
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
EOF
```

```yaml
config:
  watch_paths:
    /home/alice/.aws/credentials: rwa
```

**A decoy SSH key.** If your real key is `id_ed25519`, nothing should ever read
`id_rsa`. Create one (any key, never added to a server) and watch it:

```yaml
    /home/alice/.ssh/id_rsa: rwa
```

`ssh` itself tries `id_rsa` on every connection unless an `IdentityFile` is
set, so add `IdentityFile ~/.ssh/id_ed25519` under `Host *` in
`~/.ssh/config` first.

**Login and boot scripts.** Persistence often goes into `~/.bashrc`,
`~/.profile`, `/etc/profile.d` or `/etc/rc.local` (systemd still runs
`rc.local` if it appears and is executable, though most systems have none).
Watch them with `wa`, not `r`: your shell reads them every
time it starts.

```yaml
    /home/alice/.bashrc: wa
    /home/alice/.profile: wa
    /etc/profile.d: wa
    /etc/rc.local: wa
```

**Other credential stores nobody on your box uses:** `~/.kube/config`,
`~/.docker/config.json`, `~/.git-credentials`, `~/.pgpass`, `~/.netrc`,
`~/.config/gcloud/credentials.db`. Pick ones for tools you *don't* use; a
canary for a tool you do use alerts every time you use it.

**Mind the readers you forgot about.** Backup software, desktop file indexers
and IDEs walking your home directory read everything, canaries included. If an
alert names one of those as the executable, either exclude the file from that
tool or move the canary.

## Enabling

```bash
sudo fogbot skill enable file-watch   # shows the auditctl rules for approval
```
