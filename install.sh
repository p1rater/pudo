#!/usr/bin/env bash
# =============================================================================
#  pudo installer
#  Run from the directory containing all pudo files:
#    sudo bash install.sh
# =============================================================================

set -euo pipefail

RED='\033[1;31m'
GRN='\033[1;32m'
YLW='\033[1;33m'
CYN='\033[1;36m'
RST='\033[0m'

info()  { echo -e "${CYN}[pudo]${RST} $*"; }
ok()    { echo -e "${GRN}[pudo]${RST} $*"; }
warn()  { echo -e "${YLW}[pudo]${RST} $*"; }
die()   { echo -e "${RED}[pudo]${RST} $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] && die "Must be run as root:  sudo bash install.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Required files ────────────────────────────────────────────────────────────
for f in pudo_wrapper.c pudo_internal.py pudo.conf; do
    [[ -f "$SCRIPT_DIR/$f" ]] || die "Missing file: $f  (run from the pudo directory)"
done

# ── Paths ─────────────────────────────────────────────────────────────────────
BIN_DIR="/usr/local/bin"
LIB_DIR="/usr/local/lib/pudo"
CONF_DIR="/etc/pudo"
RULES_DIR="$CONF_DIR/rules.d"
RUN_DIR="/run/pudo"
LOG_FILE="/var/log/pudo.log"

# ── 1. Build the C wrapper ────────────────────────────────────────────────────
info "Compiling C wrapper..."
gcc -O2 -Wall -Wextra \
    "$SCRIPT_DIR/pudo_wrapper.c" \
    -o "$SCRIPT_DIR/pudo_bin" \
    || die "gcc failed. Install gcc:  sudo pacman -S gcc  or  sudo apt install gcc"
ok "Compiled: pudo_bin"

# ── 2. Install C binary (SUID root) ──────────────────────────────────────────
install -m 0755 -o root -g root "$SCRIPT_DIR/pudo_bin"  "$BIN_DIR/pudo"
chown root:root "$BIN_DIR/pudo"
chmod 4755      "$BIN_DIR/pudo"
rm -f "$SCRIPT_DIR/pudo_bin"
ok "Installed SUID binary: $BIN_DIR/pudo (4755 root:root)"

# ── 3. Install Python engine ──────────────────────────────────────────────────
mkdir -p "$LIB_DIR"
install -m 0755 -o root -g root "$SCRIPT_DIR/pudo_internal.py" "$LIB_DIR/pudo_internal.py"
ok "Installed engine: $LIB_DIR/pudo_internal.py"

# ── 4. Install config ─────────────────────────────────────────────────────────
mkdir -p "$CONF_DIR" "$RULES_DIR"
chmod 700 "$CONF_DIR" "$RULES_DIR"

if [[ ! -f "$CONF_DIR/pudo.conf" ]]; then
    install -m 0600 -o root -g root "$SCRIPT_DIR/pudo.conf" "$CONF_DIR/pudo.conf"
    ok "Installed config: $CONF_DIR/pudo.conf"
else
    warn "Existing config kept: $CONF_DIR/pudo.conf"
fi

# Install default rules only if they don't exist
for rules_file in 00-defaults.rules local.rules; do
    src="$SCRIPT_DIR/$rules_file"
    dst="$RULES_DIR/$rules_file"
    if [[ -f "$src" && ! -f "$dst" ]]; then
        install -m 0600 -o root -g root "$src" "$dst"
        ok "Installed rules: $dst"
    elif [[ ! -f "$src" ]]; then
        warn "Rules file not found in package: $rules_file  (skipping)"
    else
        warn "Existing rules kept: $dst"
    fi
done

# ── 5. Runtime dirs & log ─────────────────────────────────────────────────────
mkdir -p "$RUN_DIR"
chmod 1777 "$RUN_DIR"
chown root:root "$RUN_DIR"
ok "Token dir: $RUN_DIR (sticky 1777)"

touch "$LOG_FILE"
chmod 640 "$LOG_FILE"
chown root:root "$LOG_FILE"
ok "Audit log: $LOG_FILE"

# ── 6. Apply file capabilities (optional but recommended) ────────────────────
# Allows cap restriction (pudo -C ...) to work without full ambient caps.
# setcap requires libcap tools.
if command -v setcap &>/dev/null; then
    setcap "cap_setuid,cap_setgid,cap_setpcap,cap_sys_admin,cap_net_raw,cap_net_admin+ep" \
           "$BIN_DIR/pudo" 2>/dev/null && \
        ok "File capabilities set on $BIN_DIR/pudo" || \
        warn "setcap failed (non-fatal — SUID still works)"
else
    warn "setcap not found (install libcap for best capability support)"
fi

# ── 7. Verify ─────────────────────────────────────────────────────────────────
echo ""
ok "Installation complete!"
echo ""
echo -e "  ${GRN}Quick test (run as your normal user):${RST}"
echo -e "    pudo -v                         # version"
echo -e "    pudo --show-caps                # capability list with active markers"
echo -e "    pudo -l                         # rules for this user"
echo -e "    pudo id                         # run id as root"
echo -e "    pudo -C cap_net_raw ping -c2 8.8.8.8  # restricted caps"
echo -e "    pudo -k                         # revoke token"
echo -e "    pudo --shell                    # root shell"
echo ""
echo -e "  ${YLW}Add rules:${RST}  sudo nano /etc/pudo/rules.d/local.rules"
echo -e "  ${YLW}View log:${RST}   pudo --log"
echo ""
ls -la "$BIN_DIR/pudo"
