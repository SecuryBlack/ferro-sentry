#!/usr/bin/env bash
# Ferro-Sentry — Install script
# Usage (generic):    curl -fsSL https://install.ferrosentry.dev | bash
# Usage (SecuryBlack): curl -fsSL https://install.ferrosentry.dev | bash -s -- --endpoint ingest.securyblack.com --token <TOKEN>
set -euo pipefail

SB_AGENT_LABEL="ferro-sentry"
LIB_URL="https://raw.githubusercontent.com/securyblack/sb-agent-core/main/scripts/install-lib.sh"
LIB_TMP="$(mktemp)"
curl -fsSL "$LIB_URL" -o "$LIB_TMP" || { echo "ERROR: could not fetch install-lib.sh from sb-agent-core" >&2; exit 1; }
# shellcheck source=/dev/null
source "$LIB_TMP"
rm -f "$LIB_TMP"

# ─── Constants ────────────────────────────────────────────────────────────────
GITHUB_REPO="securyblack/ferro-sentry"
BINARY_NAME="ferro-sentry"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/ferro-sentry"
CONFIG_FILE="${CONFIG_DIR}/config.toml"

# ─── Argument parsing ─────────────────────────────────────────────────────────
ENDPOINT=""
TOKEN=""
MODE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --endpoint) ENDPOINT="$2"; shift 2 ;;
    --token)    TOKEN="$2";    shift 2 ;;
    --mode)     MODE="$2";     shift 2 ;;
    *) sb_die "Unknown argument: $1" ;;
  esac
done

# ─── Banner ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}  ███████╗███████╗██████╗ ██████╗  ██████╗     ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗${RESET}"
echo -e "${BOLD}  ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔═══██╗    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝${RESET}"
echo -e "${BOLD}  █████╗  █████╗  ██████╔╝██████╔╝██║   ██║    ███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ ${RESET}"
echo -e "${BOLD}  ██╔══╝  ██╔══╝  ██╔══██╗██╔══██╗██║   ██║    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  ${RESET}"
echo -e "${BOLD}  ██║     ███████╗██║  ██║██║  ██║╚██████╔╝    ███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   ${RESET}"
echo -e "${BOLD}  ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝     ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ${RESET}"
echo ""
sb_info "Server security agent installer (EDR + Posture)"
echo ""

sb_require_root
sb_require_cmds curl tar systemctl

TARGET="$(sb_detect_arch_linux)"
LATEST_VERSION="$(sb_fetch_latest_version "$GITHUB_REPO")"

ASSET_NAME="${BINARY_NAME}-${TARGET}.tar.gz"
DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${LATEST_VERSION}/${ASSET_NAME}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

sb_download_and_verify "$DOWNLOAD_URL" "${TMP_DIR}/${ASSET_NAME}"
sb_install_binary "${TMP_DIR}/${ASSET_NAME}" "$BINARY_NAME" "$INSTALL_DIR"

# ─── Configuration ────────────────────────────────────────────────────────────
mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

# Apply local_agent defaults
if [[ "${MODE:-}" == "local_agent" ]]; then
  ENDPOINT="${ENDPOINT:-http://localhost:8080}"
  sb_info "Mode: local_agent — Ferro-Sentry will send events to localhost:8080"
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

[[ -z "$ENDPOINT" ]] && sb_die "Endpoint cannot be empty"
[[ -z "$TOKEN" ]]    && sb_die "Token cannot be empty"

sb_info "Writing config to ${CONFIG_FILE}…"
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
sb_success "Config written"

# ─── systemd service ──────────────────────────────────────────────────────────
sb_write_systemd_unit "ferro-sentry" "Ferro-Sentry security monitoring agent" "${INSTALL_DIR}/${BINARY_NAME}" "$CONFIG_DIR" 5
sb_enable_start_service "ferro-sentry"

sb_success "Ferro-Sentry has been successfully installed and started!"
sb_info "Check logs with: journalctl -u ferro-sentry -f"
