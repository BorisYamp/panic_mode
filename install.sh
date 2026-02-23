#!/usr/bin/env bash
# PanicMode installer — must be run as root on Linux
# Usage: sudo ./install.sh [--config-only]

set -euo pipefail

BINARY_NAME="panicmode"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/panicmode"
DATA_DIR="/var/lib/panicmode"
LOG_DIR="/var/log/panicmode"
SERVICE_FILE="/etc/systemd/system/panicmode.service"
EXAMPLE_CONFIG="examples/config.yaml"

# ─── helpers ──────────────────────────────────────────────────────────────────

red()    { echo -e "\033[31m$*\033[0m"; }
green()  { echo -e "\033[32m$*\033[0m"; }
yellow() { echo -e "\033[33m$*\033[0m"; }

die() { red "ERROR: $*" >&2; exit 1; }

require() {
    command -v "$1" >/dev/null 2>&1 || die "'$1' is not installed"
}

# ─── checks ───────────────────────────────────────────────────────────────────

[[ $EUID -eq 0 ]] || die "Must be run as root (sudo ./install.sh)"
[[ -f "Cargo.toml" ]] || die "Run from the project root directory"

# ─── flags ────────────────────────────────────────────────────────────────────

CONFIG_ONLY=false
for arg in "$@"; do
    case "$arg" in
        --config-only) CONFIG_ONLY=true ;;
        *) die "Unknown argument: $arg" ;;
    esac
done

# ─── build ────────────────────────────────────────────────────────────────────

if [[ "$CONFIG_ONLY" == false ]]; then
    require cargo
    echo "Building release binary..."
    cargo build --release 2>&1 | tail -5
    echo ""
fi

# ─── directories ──────────────────────────────────────────────────────────────

echo "Creating directories..."
install -d -m 755 "$CONFIG_DIR"
install -d -m 755 "$DATA_DIR"
install -d -m 755 "$LOG_DIR"

# ─── binary ───────────────────────────────────────────────────────────────────

if [[ "$CONFIG_ONLY" == false ]]; then
    BINARY_PATH="target/release/$BINARY_NAME"
    [[ -f "$BINARY_PATH" ]] || die "Binary not found: $BINARY_PATH (build failed?)"

    echo "Installing binary to $INSTALL_DIR/$BINARY_NAME..."
    install -m 755 "$BINARY_PATH" "$INSTALL_DIR/$BINARY_NAME"
    green "Binary installed: $INSTALL_DIR/$BINARY_NAME"
fi

# ─── config ───────────────────────────────────────────────────────────────────

CONFIG_DEST="$CONFIG_DIR/config.yaml"
if [[ -f "$CONFIG_DEST" ]]; then
    yellow "Config already exists at $CONFIG_DEST — skipping (use --config-only to update)"
else
    if [[ -f "$EXAMPLE_CONFIG" ]]; then
        install -m 640 "$EXAMPLE_CONFIG" "$CONFIG_DEST"
        green "Config installed: $CONFIG_DEST"
        yellow "IMPORTANT: Edit $CONFIG_DEST and configure your alert channels before starting."
    else
        yellow "No example config found at $EXAMPLE_CONFIG — you must create $CONFIG_DEST manually"
    fi
fi

# ─── systemd service ──────────────────────────────────────────────────────────

if [[ -f "panicmode.service" ]]; then
    echo "Installing systemd service..."
    install -m 644 "panicmode.service" "$SERVICE_FILE"
    systemctl daemon-reload
    green "Service installed: $SERVICE_FILE"
    echo ""
    echo "To enable and start PanicMode:"
    echo "  systemctl enable --now panicmode"
    echo ""
    echo "To check status:"
    echo "  systemctl status panicmode"
    echo "  journalctl -u panicmode -f"
else
    yellow "No panicmode.service found — skipping systemd setup"
fi

# ─── done ─────────────────────────────────────────────────────────────────────

green "Installation complete."
