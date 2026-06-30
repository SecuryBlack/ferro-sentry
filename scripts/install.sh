#!/usr/bin/env bash
# Ferro-Sentry — Install script
# Usage (generic):    curl -fsSL https://install.ferrosentry.dev | bash
# Usage (SecuryBlack): curl -fsSL https://install.ferrosentry.dev | bash -s -- --endpoint ingest.securyblack.com --token <TOKEN>
set -euo pipefail

# ─── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${CYAN}${BOLD}[ferro-sentry]${RESET} $*"; }
success() { echo -e "${GREEN}${BOLD}[ferro-sentry]${RESET} $*"; }
warn()    { echo -e "${YELLOW}${BOLD}[ferro-sentry]${RESET} $*"; }
die()     { echo -e "${RED}${BOLD}[ferro-sentry] ERROR:${RESET} $*" >&2; exit 1; }

# ─── Constants ────────────────────────────────────────────────────────────────
GITHUB_REPO="securyblack/ferro-sentry"
BINARY_NAME="ferro-sentry"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/ferro-sentry"
CONFIG_FILE="${CONFIG_DIR}/config.toml"
SERVICE_FILE="/etc/systemd/system/ferro-sentry.service"

# ─── Argument parsing ─────────────────────────────────────────────────────────
ENDPOINT=""
TOKEN=""
MODE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --endpoint) ENDPOINT="$2"; shift 2 ;;
    --token)    TOKEN="$2";    shift 2 ;;
    --mode)     MODE="$2";     shift 2 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

# ─── Checks ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}  ███████╗███████╗██████╗ ██████╗  ██████╗     ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗${RESET}"
echo -e "${BOLD}  ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔═══██╗    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝${RESET}"
echo -e "${BOLD}  █████╗  █████╗  ██████╔╝██████╔╝██║   ██║    ███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ ${RESET}"
echo -e "${BOLD}  ██╔══╝  ██╔══╝  ██╔══██╗██╔══██╗██║   ██║    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  ${RESET}"
echo -e "${BOLD}  ██║     ███████╗██║  ██║██║  ██║╚██████╔╝    ███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   ${RESET}"
echo -e "${BOLD}  ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝     ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ${RESET}"
echo ""
info "Server security agent installer (EDR + Posture)"
echo ""

[[ "$EUID" -ne 0 ]] && die "This script must be run as root. Try: sudo bash"

for cmd in curl tar systemctl; do
  command -v "$cmd" &>/dev/null || die "Required command not found: ${cmd}"
done

# ─── Architecture detection ───────────────────────────────────────────────────
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)          TARGET="x86_64-unknown-linux-gnu"  ;;
  aarch64 | arm64) TARGET="aarch64-unknown-linux-gnu" ;;
  *) die "Unsupported architecture: ${ARCH}" ;;
esac

info "Detected architecture: ${ARCH} (${TARGET})"

# ─── Resolve latest release version ──────────────────────────────────────────
info "Fetching latest release from GitHub…"
LATEST_VERSION="$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" \
  | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\(.*\)".*/\1/')"

[[ -z "$LATEST_VERSION" ]] && die "Could not determine latest version. Check your internet connection."

info "Latest version: ${LATEST_VERSION}"

# ─── Download binary ──────────────────────────────────────────────────────────
ASSET_NAME="${BINARY_NAME}-${TARGET}.tar.gz"
DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${LATEST_VERSION}/${ASSET_NAME}"
CHECKSUM_URL="${DOWNLOAD_URL}.sha256"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

info "Downloading ${ASSET_NAME}…"
curl -fsSL "$DOWNLOAD_URL" -o "${TMP_DIR}/${ASSET_NAME}" \
  || die "Download failed. Is the release published with the expected asset name?"

# Verify checksum if available
if curl -fsSL "$CHECKSUM_URL" -o "${TMP_DIR}/${ASSET_NAME}.sha256" 2>/dev/null; then
  info "Verifying checksum…"
  (cd "$TMP_DIR" && sha256sum -c "${ASSET_NAME}.sha256" --quiet) \
    || die "Checksum verification failed"
  success "Checksum OK"
else
  warn "No checksum file found, skipping verification"
fi

# ─── Install binary ───────────────────────────────────────────────────────────
info "Installing binary to ${INSTALL_DIR}/${BINARY_NAME}…"
tar -xzf "${TMP_DIR}/${ASSET_NAME}" -C "$TMP_DIR"
install -m 755 "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
success "Binary installed"

# ─── Configuration ────────────────────────────────────────────────────────────
mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

# Apply local_agent defaults
if [[ "${MODE:-}" == "local_agent" ]]; then
  ENDPOINT="${ENDPOINT:-http://localhost:8080}"
  info "Mode: local_agent — Ferro-Sentry will send events to localhost:8080"
fi

# Ask interactively if not provided via arguments
if [[ -z "$ENDPOINT" ]]; then
  echo ""
  read -rp "$(echo -e "${BOLD}  SecuryBlack API endpoint (e.g. https://api.securyblack.com):${RESET} ")" ENDPOINT </dev/tty
fi
if [[ -z "$TOKEN" ]]; then
  read -rsp "$(echo -e "${BOLD}  Auth token:${RESET} ")" TOKEN </dev/tty
  echo ""
fi

[[ -z "$ENDPOINT" ]] && die "Endpoint cannot be empty"
[[ -z "$TOKEN" ]]    && die "Token cannot be empty"

info "Writing config to ${CONFIG_FILE}…"
cat > "$CONFIG_FILE" <<EOF
# Ferro-Sentry configuration
# Do not share this file — it contains your auth token.
mode = "${MODE:-direct}"
api_url = "${ENDPOINT}"
token = "${TOKEN}"
log_level = "info"
local_file_path = "/var/log/ferro-sentry_events.jsonl"
EOF
chmod 600 "$CONFIG_FILE"
success "Config written"

# ─── systemd service ──────────────────────────────────────────────────────────
info "Creating systemd service…"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Ferro-Sentry security monitoring agent
Documentation=https://github.com/${GITHUB_REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${BINARY_NAME}
Restart=always
RestartSec=5
WorkingDirectory=${CONFIG_DIR}
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

info "Reloading systemd, enabling and starting service…"
systemctl daemon-reload
systemctl enable --now ferro-sentry

success "Ferro-Sentry has been successfully installed and started!"
info "Check logs with: journalctl -u ferro-sentry -f"
