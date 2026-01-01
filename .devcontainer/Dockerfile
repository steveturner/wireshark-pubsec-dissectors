FROM mcr.microsoft.com/devcontainers/base:ubuntu-22.04

# Install Wireshark/tshark and Lua
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
        tshark \
        wireshark-common \
        lua5.2 \
        liblua5.2-dev \
        luarocks \
        git \
        curl \
        ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Allow non-root user to capture packets (for testing)
RUN setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/dumpcap || true

# Create Wireshark plugin directory for vscode user
RUN mkdir -p /home/vscode/.local/lib/wireshark/plugins \
    && chown -R vscode:vscode /home/vscode/.local

# Set up environment
ENV WIRESHARK_PLUGIN_DIR=/home/vscode/.local/lib/wireshark/plugins

WORKDIR /workspace

# Verify tshark installation
RUN tshark --version
