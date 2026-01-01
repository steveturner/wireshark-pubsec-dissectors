#!/bin/bash
# TAK Wireshark Plugin Installer
# Supports: macOS, Linux

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAK_PLUGIN="$SCRIPT_DIR/tak.lua"
OMNI_PLUGIN="$SCRIPT_DIR/omni.lua"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check if plugin files exist
if [ ! -f "$TAK_PLUGIN" ]; then
    error "Plugin file not found: $TAK_PLUGIN"
fi
if [ ! -f "$OMNI_PLUGIN" ]; then
    error "Plugin file not found: $OMNI_PLUGIN"
fi

# Detect OS and set plugin directory
detect_plugin_dir() {
    case "$(uname -s)" in
        Darwin)
            # macOS - prefer user directory
            PLUGIN_DIR="$HOME/.local/lib/wireshark/plugins"
            ALT_PLUGIN_DIR="/Applications/Wireshark.app/Contents/PlugIns/wireshark"
            ;;
        Linux)
            # Linux - prefer user directory
            PLUGIN_DIR="$HOME/.local/lib/wireshark/plugins"
            ALT_PLUGIN_DIR="/usr/lib/wireshark/plugins"
            # Also check for x86_64 path
            if [ -d "/usr/lib/x86_64-linux-gnu/wireshark/plugins" ]; then
                ALT_PLUGIN_DIR="/usr/lib/x86_64-linux-gnu/wireshark/plugins"
            fi
            ;;
        CYGWIN*|MINGW*|MSYS*)
            # Windows via Git Bash/MSYS
            PLUGIN_DIR="$APPDATA/Wireshark/plugins"
            ALT_PLUGIN_DIR="$PROGRAMFILES/Wireshark/plugins"
            ;;
        *)
            error "Unsupported operating system: $(uname -s)"
            ;;
    esac
}

# Find Wireshark version for versioned plugin directory
get_wireshark_version() {
    local ws_version=""

    # Try to get version from wireshark or tshark
    if command -v wireshark &> /dev/null; then
        ws_version=$(wireshark --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
    elif command -v tshark &> /dev/null; then
        ws_version=$(tshark --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
    fi

    echo "$ws_version"
}

# Install the plugins
install_plugin() {
    local target_dir="$1"
    local version="$2"

    # Create versioned subdirectory if version is known
    if [ -n "$version" ]; then
        target_dir="$target_dir/$version"
    fi

    info "Installing to: $target_dir"

    # Create directory if it doesn't exist
    mkdir -p "$target_dir"

    # Copy plugins
    cp "$TAK_PLUGIN" "$target_dir/"
    cp "$OMNI_PLUGIN" "$target_dir/"

    if [ -f "$target_dir/tak.lua" ] && [ -f "$target_dir/omni.lua" ]; then
        info "Successfully installed tak.lua and omni.lua"
        return 0
    else
        return 1
    fi
}

# Main installation logic
main() {
    echo "========================================"
    echo "  TAK Wireshark Plugin Installer"
    echo "========================================"
    echo

    detect_plugin_dir
    local ws_version=$(get_wireshark_version)

    if [ -n "$ws_version" ]; then
        info "Detected Wireshark version: $ws_version"
    else
        warn "Could not detect Wireshark version"
    fi

    # Try user directory first
    if install_plugin "$PLUGIN_DIR" "$ws_version"; then
        echo
        info "Installation complete!"
        info "Restart Wireshark to load the plugin."
        echo
        echo "Plugin location: $PLUGIN_DIR${ws_version:+/$ws_version}/"
        exit 0
    fi

    # Try alternative directory (may need sudo on Linux)
    warn "Could not install to user directory, trying system directory..."

    if [ -w "$ALT_PLUGIN_DIR" ] || [ "$(uname -s)" = "Darwin" ]; then
        if install_plugin "$ALT_PLUGIN_DIR" "$ws_version"; then
            echo
            info "Installation complete!"
            info "Restart Wireshark to load the plugin."
            exit 0
        fi
    else
        warn "System directory requires elevated privileges."
        echo "Run: sudo $0"
        echo "Or manually copy tak.lua and omni.lua to: $ALT_PLUGIN_DIR"
    fi

    error "Installation failed"
}

# Handle uninstall flag
if [ "$1" = "--uninstall" ] || [ "$1" = "-u" ]; then
    echo "Uninstalling TAK/OMNI plugins..."
    detect_plugin_dir
    ws_version=$(get_wireshark_version)

    for dir in "$PLUGIN_DIR" "$ALT_PLUGIN_DIR"; do
        for plugin in "tak.lua" "omni.lua"; do
            for target in "$dir/$plugin" "$dir/$ws_version/$plugin"; do
                if [ -f "$target" ]; then
                    rm -f "$target"
                    info "Removed: $target"
                fi
            done
        done
    done

    info "Uninstallation complete"
    exit 0
fi

main "$@"
