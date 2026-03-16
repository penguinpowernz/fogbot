# Troubleshooting Guide

## TLS Certificate Errors

### Symptom
```
Failed to send startup message: api call failed: Post "https://api.telegram.org/bot...":
tls: failed to verify certificate: x509: certificate signed by unknown authority
```

### Causes
1. Docker container missing CA certificates
2. System CA certificates outdated
3. Network proxy interfering with TLS

### Solutions

#### Option 1: Rebuild Docker Image (Recommended)
The Dockerfile now includes CA certificate updates:

```bash
# Rebuild the image
make docker-build

# Or manually:
docker-compose build --no-cache
```

The updated Dockerfile:
- Installs `ca-certificates` package
- Runs `update-ca-certificates`
- Sets `SSL_CERT_FILE` and `SSL_CERT_DIR` environment variables

#### Option 2: Use FOGBOT_INSECURE_TLS (Testing Only)
**WARNING: Only for testing! Do not use in production!**

```yaml
# docker-compose.yml
environment:
  - FOGBOT_INSECURE_TLS=true  # Skips TLS verification
```

Or when running directly:
```bash
FOGBOT_INSECURE_TLS=true ./fogbot daemon
```

#### Option 3: Install CA Certificates in Running Container
```bash
# Enter the container
docker-compose exec fogbot bash

# Update certificates
apt-get update
apt-get install -y ca-certificates
update-ca-certificates

# Exit and restart
exit
docker-compose restart
```

#### Option 4: Use Host Network (Development)
```yaml
# docker-compose.yml
services:
  fogbot:
    network_mode: host
```

### Verification

Test the connection manually:
```bash
# In container
docker-compose exec fogbot bash

# Test with curl
curl -v https://api.telegram.org/botYOUR_TOKEN/getMe

# Test with openssl
openssl s_client -connect api.telegram.org:443 -showcerts
```

Check certificate paths:
```bash
ls -la /etc/ssl/certs/ca-certificates.crt
echo $SSL_CERT_FILE
echo $SSL_CERT_DIR
```

---

## Telegram Bot Not Responding

### Check Authorization

```bash
# View logs for auth code
docker-compose logs fogbot | grep "Authorization code"

# Should see something like:
# Authorization code: FOG-A3X9-K2M7
```

### Verify Token

```bash
# Test token with curl
curl https://api.telegram.org/botYOUR_TOKEN/getMe
```

Should return JSON with bot info. If it returns error, your token is invalid.

### Check Chat ID

After authorization, verify chat_id is saved:
```bash
docker-compose exec fogbot cat /var/lib/fogbot/state.json
```

Should show:
```json
{
  "authorized_chat": "123456789",
  "authorized_at": "2026-03-08T...",
  "code_used": true
}
```

---

## Skills Not Loading

### Check Symlinks
```bash
# List enabled skills
ls -la etc/fogbot/skills-enabled/

# Should see symlinks like:
# 100-ssh-monitor.yaml -> ../skills-available/100-ssh-monitor.yaml
```

### Verify YAML Syntax
```bash
# Check a skill file
cat etc/fogbot/skills-available/100-ssh-monitor.yaml

# Validate YAML (if you have yamllint)
yamllint etc/fogbot/skills-available/*.yaml
```

### Check Logs
```bash
docker-compose logs fogbot | grep -i skill
```

---

## Permission Denied Errors

### Required Capabilities
fogbot needs these Linux capabilities:
- `CAP_NET_ADMIN` - For iptables rules
- `CAP_AUDIT_CONTROL` - For auditd configuration
- `CAP_SYS_PTRACE` - For process monitoring

### Verify Capabilities (Docker)
```yaml
# docker-compose.yml already includes:
cap_add:
  - NET_ADMIN
  - AUDIT_CONTROL
  - SYS_PTRACE
```

### Running Without Docker
```bash
# Option 1: Run as root
sudo ./fogbot daemon

# Option 2: Set capabilities on binary
sudo setcap 'cap_net_admin,cap_audit_control,cap_sys_ptrace=+ep' ./fogbot
./fogbot daemon
```

---

## Dry-Run Mode Issues

### Enable Dry-Run
```bash
# Environment variable
FOGBOT_DRY_RUN=true ./fogbot daemon

# Or in docker-compose.yml:
environment:
  - FOGBOT_DRY_RUN=true
```

### Verify Dry-Run Active
Look for logs like:
```
[DRY-RUN] Would write to /etc/iptables/rules.d/90-fogbot-port-tripwires.rules
[DRY-RUN] Would remove /etc/audit/rules.d/90-fogbot-file-watch.rules
```

---

## Build Errors

### Missing Dependencies
```bash
go mod download
go mod tidy
```

### CGO Issues
fogbot doesn't use CGO by default. If you see CGO errors:
```bash
CGO_ENABLED=0 go build -o fogbot ./cmd/fogbot
```

---

## Docker Issues

### Image Won't Build
```bash
# Clean build
docker-compose build --no-cache

# Check disk space
docker system df
docker system prune
```

### Container Exits Immediately
```bash
# Check logs
docker-compose logs fogbot

# Run with shell to debug
docker-compose run --rm fogbot /bin/bash
```

### Volume Permission Issues
```bash
# Fix permissions
docker-compose exec fogbot chown -R root:root /var/lib/fogbot
docker-compose exec fogbot chmod 755 /var/lib/fogbot
```

---

## Network Connectivity

### Test from Container
```bash
docker-compose exec fogbot bash

# Test DNS
nslookup api.telegram.org

# Test connectivity
ping -c 3 api.telegram.org

# Test HTTPS
curl -v https://api.telegram.org

# Check routes
ip route
```

### Proxy Settings
If behind a corporate proxy:
```yaml
# docker-compose.yml
environment:
  - HTTP_PROXY=http://proxy.example.com:8080
  - HTTPS_PROXY=http://proxy.example.com:8080
  - NO_PROXY=localhost,127.0.0.1
```

---

## Rate Limiting

### Authorized Chat Rate Limited
Default: 10 commands per 60 seconds

Increase if needed (edit `internal/auth/auth.go`):
```go
rateLimiter: auth.NewRateLimiter(20, 3, 60*time.Second)  // 20 instead of 10
```

### Unauthorized Chats
Default: 3 messages lifetime, then permanently ignored

This is intentional to prevent abuse.

---

## Getting More Help

1. **Check logs**: `docker-compose logs -f fogbot`
2. **Increase verbosity**: Add `log.SetLevel(log.DebugLevel)` to main.go
3. **Test components individually**: Use the CLI without running daemon
4. **Review plan.md**: Full specification and architecture details

### Useful Debug Commands

```bash
# Show environment
docker-compose exec fogbot env | grep FOGBOT

# Show process tree
docker-compose exec fogbot ps auxf

# Show network connections
docker-compose exec fogbot ss -tulpn

# Show file descriptors
docker-compose exec fogbot ls -la /proc/$PID/fd

# Show system capabilities
docker-compose exec fogbot capsh --print
```
