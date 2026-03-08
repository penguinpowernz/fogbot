FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    auditd \
    iptables \
    iproute2 \
    procps \
    coreutils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /etc/fogbot/skills-available \
             /etc/fogbot/skills-enabled \
             /var/lib/fogbot \
             /var/log/fogbot

# Copy the entire package structure
COPY etc/ /etc/
COPY usr/ /usr/
COPY var/ /var/

# Ensure binary is executable
RUN chmod +x /usr/local/bin/fogbot

# Create state directory with proper permissions
RUN chown -R root:root /var/lib/fogbot && \
    chmod 755 /var/lib/fogbot

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD /usr/local/bin/fogbot version || exit 1

# Run as root (required for monitoring capabilities)
USER root

WORKDIR /var/lib/fogbot

# Default command
CMD ["/usr/local/bin/fogbot", "daemon"]
