# fogbot Contrib Files

This directory contains default configuration files that are installed by the Debian package's postinst script.

## How it works

During package installation (`dpkg -i fogbot_*.deb`), the postinst script:

1. **config.yaml**: Copies to `/etc/fogbot/config.yaml` ONLY if it doesn't exist
   - On fresh install: gets the default config
   - On upgrade: existing config is preserved

2. **skills-available/*.yaml**: Copies individual skill files to `/etc/fogbot/skills-available/` ONLY if missing
   - New skills added in package updates are installed automatically
   - Modified skill files are never overwritten

## For users

Your actual configuration lives in `/etc/fogbot/`:
- `/etc/fogbot/config.yaml` - Main config (edit freely)
- `/etc/fogbot/skills-available/` - Skill definitions (edit freely)
- `/etc/fogbot/skills-enabled/` - Symlinks to enabled skills

Package upgrades will never overwrite your edits.

## For developers

When adding new skills or updating defaults:
1. Add/update files in `usr/share/fogbot/contrib/`
2. The postinst script will copy new files on package upgrade
3. Existing user modifications are always preserved
