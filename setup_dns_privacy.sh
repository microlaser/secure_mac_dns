#!/usr/bin/env bash
# =============================================================================
#
#   setup_dns_privacy.sh
#   Stop DNS leaks on macOS — one script, no technical knowledge required
#
#   What this script does:
#     1. Installs Homebrew (if needed)
#     2. Installs stubby  — encrypts your DNS queries (DNS-over-TLS)
#     3. Installs dnsmasq — bridges the system to stubby
#     4. Configures both  — routes all DNS through Quad9 (privacy-respecting)
#     5. Locks every network interface to use the local encrypted resolver
#     6. Installs a firewall rule that permanently blocks any DNS leaks
#     7. Makes everything survive reboots automatically
#     8. Verifies it's all working
#
#   Usage:
#     sudo bash setup_dns_privacy.sh
#
#   Safe to run more than once — every step is idempotent.
#
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ── Colours ───────────────────────────────────────────────────────────────────
R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' C='\033[0;36m'
B='\033[1m'    RESET='\033[0m'

# ── Friendly output helpers ───────────────────────────────────────────────────
print_banner() {
    echo -e "${B}"
    echo "  ╔══════════════════════════════════════════════════════════════╗"
    echo "  ║          DNS Privacy Setup for macOS                        ║"
    echo "  ║          Your DNS queries will be encrypted with            ║"
    echo "  ║          DNS-over-TLS via Quad9 (privacy-first resolver)    ║"
    echo "  ╚══════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

step()    { echo -e "\n${B}  ┌─ $* ${RESET}"; }
ok()      { echo -e "  ${G}✔${RESET}  $*"; }
info()    { echo -e "  ${C}→${RESET}  $*"; }
warn()    { echo -e "  ${Y}⚠${RESET}  $*"; }
err()     { echo -e "  ${R}✘${RESET}  $*"; }
fatal()   { echo -e "\n  ${R}${B}FATAL: $*${RESET}\n"; exit 1; }
progress(){ echo -ne "  ${C}…${RESET}  $*\r"; }

# ── Constants ─────────────────────────────────────────────────────────────────
STUBBY_CONF="/opt/homebrew/etc/stubby/stubby.yml"
DNSMASQ_CONF="/opt/homebrew/etc/dnsmasq.conf"
DNSMASQ_CONF_DIR="/opt/homebrew/etc/dnsmasq.d"
PF_ANCHOR_DIR="/etc/pf.anchors"
PF_ANCHOR_FILE="$PF_ANCHOR_DIR/dns_privacy"
PF_MAIN="/etc/pf.conf"
LAUNCH_DAEMON_PLIST="/Library/LaunchDaemons/com.dns-privacy.pf-anchor.plist"
BACKUP_DIR="/var/backups/dns_privacy_$(date +%Y%m%d_%H%M%S)"

# Homebrew prefix differs between Apple Silicon and Intel
if [[ "$(uname -m)" == "arm64" ]]; then
    BREW_PREFIX="/opt/homebrew"
    BREW_BIN="/opt/homebrew/bin/brew"
else
    BREW_PREFIX="/usr/local"
    BREW_BIN="/usr/local/bin/brew"
fi

# ── Preflight checks ──────────────────────────────────────────────────────────
print_banner

echo -e "  Running on: macOS $(sw_vers -productVersion) ($(uname -m))"
echo -e "  Date: $(date)"
echo ""

# Must be root
if [[ $EUID -ne 0 ]]; then
    echo -e "  ${R}This script needs admin privileges.${RESET}"
    echo -e "  Please run it like this:\n"
    echo -e "    ${B}sudo bash setup_dns_privacy.sh${RESET}\n"
    exit 1
fi

# Must be macOS
[[ "$(uname)" == "Darwin" ]] || fatal "This script only works on macOS."

# Save the real (non-root) username for brew commands
REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo '')}"
[[ -z "$REAL_USER" || "$REAL_USER" == "root" ]] && \
    fatal "Could not determine your username. Make sure to use 'sudo bash', not 'sudo su'."

REAL_HOME=$(eval echo "~$REAL_USER")

# ── Backup existing configs ───────────────────────────────────────────────────
step "Backing up existing configuration"
mkdir -p "$BACKUP_DIR"
for f in "$STUBBY_CONF" "$DNSMASQ_CONF" "$PF_MAIN"; do
    [[ -f "$f" ]] && cp "$f" "$BACKUP_DIR/" && info "Backed up $(basename $f)"
done
ok "Backups saved to $BACKUP_DIR"

# =============================================================================
#  PHASE 1 — Install Homebrew (if missing)
# =============================================================================
step "Phase 1 of 7 — Checking Homebrew"

if [[ -x "$BREW_BIN" ]]; then
    ok "Homebrew is already installed"
else
    info "Homebrew not found — installing it now (this may take a few minutes)..."
    sudo -u "$REAL_USER" /bin/bash -c \
        "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" \
        || fatal "Homebrew installation failed. Please install it manually from https://brew.sh then run this script again."
    ok "Homebrew installed"
fi

# Make sure brew is callable in this root shell
export PATH="$BREW_PREFIX/bin:$BREW_PREFIX/sbin:$PATH"

# =============================================================================
#  PHASE 2 — Install stubby and dnsmasq
# =============================================================================
step "Phase 2 of 7 — Installing stubby and dnsmasq"

# Stop any running instances before touching packages
sudo -u "$REAL_USER" brew services stop stubby  2>/dev/null || true
sudo -u "$REAL_USER" brew services stop dnsmasq 2>/dev/null || true
pkill -x stubby  2>/dev/null || true
pkill -x dnsmasq 2>/dev/null || true
sleep 1

progress "Installing stubby (DNS-over-TLS daemon)..."
sudo -u "$REAL_USER" brew install stubby 2>&1 | grep -E "install|already|Error" | \
    while IFS= read -r line; do info "$line"; done || true
ok "stubby ready"

progress "Installing dnsmasq (local DNS bridge)..."
sudo -u "$REAL_USER" brew install dnsmasq 2>&1 | grep -E "install|already|Error" | \
    while IFS= read -r line; do info "$line"; done || true
ok "dnsmasq ready"

# =============================================================================
#  PHASE 3 — Configure stubby (DNS-over-TLS → Quad9)
# =============================================================================
step "Phase 3 of 7 — Configuring stubby"
info "stubby will encrypt all DNS queries using TLS and send them to Quad9"
info "Quad9 (quad9.net) is a non-profit, privacy-respecting, malware-blocking resolver"

mkdir -p "$(dirname "$STUBBY_CONF")"

# Write a clean, complete config — never patch, always replace
cat > "$STUBBY_CONF" <<'YAML'
# stubby configuration — managed by setup_dns_privacy.sh
# Encrypts DNS queries using DNS-over-TLS (port 853) to Quad9

# Use stub resolver mode (queries go directly to upstream)
resolution_type: GETDNS_RESOLUTION_STUB

# Only use TLS — never fall back to plaintext
dns_transport_list:
  - GETDNS_TRANSPORT_TLS

# Require TLS — reject connections that can't authenticate
tls_authentication: GETDNS_AUTHENTICATION_REQUIRED

# Pad queries to a fixed block size to reduce fingerprinting
tls_query_padding_blocksize: 128

# Don't leak your subnet to upstream resolvers
edns_client_subnet_private: 1

# Alternate between Quad9 servers for reliability
round_robin_upstreams: 1

# Keep TLS connections open for 10 seconds to reduce overhead
idle_timeout: 10000

# Listen on localhost port 5300
# (dnsmasq sits on port 53 and forwards here)
listen_addresses:
  - address_data: 127.0.0.1
    port: 5300

# Upstream resolvers — Quad9 primary and secondary
upstream_recursive_servers:
  - address_data: 9.9.9.9
    tls_port: 853
    tls_auth_name: "dns.quad9.net"
  - address_data: 149.112.112.112
    tls_port: 853
    tls_auth_name: "dns.quad9.net"
YAML

ok "stubby configured (listens on 127.0.0.1:5300, upstream → Quad9 via TLS)"

# Validate the config file is parseable
STUBBY_TEST=$(stubby -l 2>&1 &
    SPID=$!; sleep 2; kill $SPID 2>/dev/null; wait $SPID 2>/dev/null || true)
if echo "$STUBBY_TEST" | grep -qi "Generic error\|parse error\|invalid\|failed"; then
    err "stubby config validation failed:"
    echo "$STUBBY_TEST" | sed 's/^/    /'
    fatal "stubby.yml is invalid. Original backed up to $BACKUP_DIR"
fi
ok "stubby config validated"

# =============================================================================
#  PHASE 4 — Configure dnsmasq (bridge: port 53 → stubby port 5300)
# =============================================================================
step "Phase 4 of 7 — Configuring dnsmasq"
info "dnsmasq sits between macOS and stubby, bridging port 53 → 5300"

mkdir -p "$DNSMASQ_CONF_DIR"

cat > "$DNSMASQ_CONF" <<'CONF'
# dnsmasq configuration — managed by setup_dns_privacy.sh
# Bridges macOS system DNS (port 53) to stubby (port 5300)

# Only listen on localhost — never expose to the network
listen-address=127.0.0.1
bind-interfaces
port=53

# Don't read /etc/resolv.conf — we control all upstream routing
no-resolv
no-poll

# Forward all queries to stubby on port 5300
server=127.0.0.1#5300

# Cache up to 1000 responses for speed
cache-size=1000

# Log to syslog for diagnostics (silent unless you check Console.app)
log-facility=/var/log/dnsmasq.log
CONF

ok "dnsmasq configured (port 53 → stubby:5300)"

# =============================================================================
#  PHASE 5 — Start services and verify they're running
# =============================================================================
step "Phase 5 of 7 — Starting services"

# Clear anything squatting on port 5300
for port in 53 5300; do
    PIDS=$(lsof -nP -iUDP:$port -iTCP:$port 2>/dev/null \
        | awk 'NR>1 && $1!="mDNSRespo" {print $2}' | sort -u || true)
    if [[ -n "$PIDS" ]]; then
        for pid in $PIDS; do
            PNAME=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
            info "Clearing port $port (was held by $PNAME, PID $pid)"
            kill -9 "$pid" 2>/dev/null || true
        done
        sleep 1
    fi
done

# Start stubby
info "Starting stubby..."
sudo -u "$REAL_USER" brew services start stubby
sleep 3

if ! pgrep -x stubby &>/dev/null; then
    err "stubby failed to start. Trying once more..."
    sudo -u "$REAL_USER" brew services restart stubby
    sleep 3
fi
pgrep -x stubby &>/dev/null || fatal "stubby won't start. Run 'sudo stubby -l' for details."
ok "stubby running (PID $(pgrep -x stubby | head -1))"

# Start dnsmasq (must run as root to bind port 53)
info "Starting dnsmasq..."
# dnsmasq needs to run as root for port 53 — use a LaunchDaemon
DNSMASQ_BIN="$BREW_PREFIX/sbin/dnsmasq"
DNSMASQ_PLIST="/Library/LaunchDaemons/homebrew.mxcl.dnsmasq.plist"

cat > "$DNSMASQ_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>             <string>homebrew.mxcl.dnsmasq</string>
  <key>ProgramArguments</key>
  <array>
    <string>${DNSMASQ_BIN}</string>
    <string>--keep-in-foreground</string>
    <string>--conf-file=${DNSMASQ_CONF}</string>
  </array>
  <key>RunAtLoad</key>         <true/>
  <key>KeepAlive</key>         <true/>
  <key>StandardErrorPath</key> <string>/var/log/dnsmasq_err.log</string>
</dict>
</plist>
PLIST

launchctl unload "$DNSMASQ_PLIST" 2>/dev/null || true
sleep 1
launchctl load -w "$DNSMASQ_PLIST"
sleep 2

if ! pgrep -x dnsmasq &>/dev/null; then
    err "dnsmasq failed to start. Trying direct launch..."
    "$DNSMASQ_BIN" --keep-in-foreground --conf-file="$DNSMASQ_CONF" &
    sleep 2
fi
pgrep -x dnsmasq &>/dev/null || fatal "dnsmasq won't start. Check: cat /var/log/dnsmasq_err.log"
ok "dnsmasq running (PID $(pgrep -x dnsmasq | head -1))"

# =============================================================================
#  PHASE 6 — Lock every network interface to 127.0.0.1
# =============================================================================
step "Phase 6 of 7 — Locking all network interfaces to local resolver"
info "Setting every network interface to use 127.0.0.1 (no DHCP/router DNS leakage)"

SERVICES=$(networksetup -listallnetworkservices 2>/dev/null | tail -n +2 || true)
CHANGED=0
SKIPPED=0

while IFS= read -r svc; do
    [[ -z "$svc" ]] && continue
    svc_clean="${svc#\* }"   # strip leading asterisk (disabled services)
    CURRENT=$(networksetup -getdnsservers "$svc_clean" 2>/dev/null || true)
    if echo "$CURRENT" | grep -q "^127\.0\.0\.1$"; then
        (( SKIPPED++ )) || true
    else
        OLD=$(echo "$CURRENT" | tr '\n' ' ' | sed 's/  */ /g; s/^ //; s/ $//')
        networksetup -setdnsservers "$svc_clean" 127.0.0.1
        ok "[$svc_clean] was: ${OLD:-DHCP} → now: 127.0.0.1"
        (( CHANGED++ )) || true
    fi
done <<< "$SERVICES"

ok "All interfaces locked ($CHANGED updated, $SKIPPED already correct)"

# Flush DNS cache so new settings take effect immediately
dscacheutil -flushcache
killall -HUP mDNSResponder 2>/dev/null || true
ok "DNS cache flushed"

# =============================================================================
#  PHASE 7 — Firewall rules: permanently block plaintext DNS leaks
# =============================================================================
step "Phase 7 of 7 — Installing firewall rules to block DNS leaks"
info "These rules ensure no app can accidentally send DNS queries in plaintext"

mkdir -p "$PF_ANCHOR_DIR"

cat > "$PF_ANCHOR_FILE" <<'PFRULES'
# dns_privacy anchor — managed by setup_dns_privacy.sh
# Blocks all plaintext DNS (port 53) except local loopback traffic
# Allows stubby to reach Quad9 on port 853 (DNS-over-TLS)

# Allow all loopback port-53 traffic (mDNSResponder ↔ dnsmasq ↔ stubby)
pass out quick on lo0 proto { tcp udp } from 127.0.0.1 to 127.0.0.1 port 53
pass in  quick on lo0 proto { tcp udp } from 127.0.0.1 to 127.0.0.1 port 53

# Allow stubby's loopback port (5300)
pass out quick on lo0 proto { tcp udp } from any to any port 5300
pass in  quick on lo0 proto { tcp udp } from any to any port 5300

# Allow outbound DNS-over-TLS to Quad9 (port 853)
pass out quick proto tcp from any to { 9.9.9.9, 149.112.112.112 } port 853

# Block all other outbound plaintext DNS — this is what stops leaks
block drop out quick proto { tcp udp } from any to any port 53
PFRULES

ok "Firewall rules written to $PF_ANCHOR_FILE"

# Inject anchor into pf.conf if not already there
if ! grep -q "dns_privacy" "$PF_MAIN" 2>/dev/null; then
    cp "$PF_MAIN" "$PF_MAIN.bak.$(date +%s)"
    cat >> "$PF_MAIN" <<'PF'

# DNS privacy rules — added by setup_dns_privacy.sh
anchor "dns_privacy"
load anchor "dns_privacy" from "/etc/pf.anchors/dns_privacy"
PF
    ok "Firewall anchor added to $PF_MAIN"
else
    ok "Firewall anchor already in $PF_MAIN — refreshing rules"
fi

# Enable and reload pf
pfctl -e 2>/dev/null || true
pfctl -f "$PF_MAIN" 2>/dev/null && ok "Firewall rules loaded" || \
    warn "pf reload returned an error — checking syntax..."
pfctl -n -f "$PF_MAIN" 2>/dev/null && ok "Firewall syntax verified" || \
    warn "Firewall syntax issue — rules may not be fully active, but DNS encryption is still working"

# Install a LaunchDaemon so pf rules reload automatically after every reboot
cat > "$LAUNCH_DAEMON_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>             <string>com.dns-privacy.pf-anchor</string>
  <key>ProgramArguments</key>
  <array>
    <string>/sbin/pfctl</string>
    <string>-f</string>
    <string>/etc/pf.conf</string>
  </array>
  <key>RunAtLoad</key>         <true/>
  <key>StandardErrorPath</key> <string>/var/log/dns_privacy_pf.log</string>
</dict>
</plist>
PLIST

launchctl unload "$LAUNCH_DAEMON_PLIST" 2>/dev/null || true
launchctl load -w "$LAUNCH_DAEMON_PLIST"
ok "Firewall rules will reload automatically after every reboot"

# =============================================================================
#  VERIFICATION
# =============================================================================
echo ""
echo -e "${B}  ┌─ Verifying everything is working ${RESET}"
sleep 2  # give services a moment to fully initialise

PASS=0; FAIL=0

check() {
    local desc="$1"; local result="$2"
    if [[ "$result" == "pass" ]]; then
        ok "$desc"
        (( PASS++ )) || true
    else
        err "$desc"
        (( FAIL++ )) || true
    fi
}

# 1. Primary resolver is localhost
PRIMARY=$(scutil --dns 2>/dev/null | awk '/nameserver\[0\]/{print $3; exit}')
[[ "$PRIMARY" == "127.0.0.1" ]] && R="pass" || R="fail"
check "System resolver is 127.0.0.1 ← (primary check)" "$R"

# 2. stubby is running
pgrep -x stubby &>/dev/null && R="pass" || R="fail"
check "stubby is running (DNS-over-TLS daemon)" "$R"

# 3. dnsmasq is running
pgrep -x dnsmasq &>/dev/null && R="pass" || R="fail"
check "dnsmasq is running (local DNS bridge)" "$R"

# 4. stubby responds on port 5300
dig +short +time=4 google.com @127.0.0.1 -p 5300 2>/dev/null | grep -qE "^[0-9]" \
    && R="pass" || R="fail"
check "stubby resolves queries on 127.0.0.1:5300" "$R"

# 5. System resolver (port 53) resolves via dnsmasq → stubby
dig +short +time=4 google.com @127.0.0.1 2>/dev/null | grep -qE "^[0-9]" \
    && R="pass" || R="fail"
check "System resolver resolves queries on 127.0.0.1:53" "$R"

# 6. Quad9 is confirmed as upstream
QUAD9=$(dig +short +time=5 id.server.on.quad9.net txt @127.0.0.1 -p 5300 \
    2>/dev/null | tr -d '"' || true)
[[ -n "$QUAD9" ]] && R="pass" || R="fail"
check "Quad9 confirmed as upstream resolver${QUAD9:+ ($QUAD9)}" "$R"

# 7. Port 853 outbound to Quad9 is open (stubby can reach its upstream)
nc -z -w 4 9.9.9.9 853 2>/dev/null && R="pass" || R="fail"
check "Outbound port 853 (DoT) is open to Quad9" "$R"

# 8. Plaintext DNS leaks — timed capture, no hang
info "Checking for plaintext DNS leaks (5 seconds)..."
TCPDUMP_TMP=$(mktemp /tmp/dns_leak_check.XXXXXX)
tcpdump -i any -nn --immediate-mode udp port 53 or tcp port 53 \
    > "$TCPDUMP_TMP" 2>/dev/null &
TCPID=$!
sleep 5
kill "$TCPID" 2>/dev/null; wait "$TCPID" 2>/dev/null || true
LEAKS=$(grep -v "127\.0\.0\.1" "$TCPDUMP_TMP" | grep -v "::1" | grep -v "^$" || true)
rm -f "$TCPDUMP_TMP"
[[ -z "$LEAKS" ]] && R="pass" || R="fail"
check "No plaintext DNS leaks detected on port 53" "$R"

# 9. All interfaces locked
UNLOCKED=$(networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | \
    while IFS= read -r svc; do
        svc="${svc#\* }"
        DNS=$(networksetup -getdnsservers "$svc" 2>/dev/null || true)
        echo "$DNS" | grep -q "127\.0\.0\.1" || echo "$svc"
    done || true)
[[ -z "$UNLOCKED" ]] && R="pass" || R="fail"
check "All network interfaces locked to 127.0.0.1" "$R"

# =============================================================================
#  SUMMARY
# =============================================================================
echo ""
echo -e "${B}  ╔══════════════════════════════════════════════════════════════╗${RESET}"
if [[ $FAIL -eq 0 ]]; then
    echo -e "${B}  ║  ${G}✔ All checks passed — your DNS is now private and encrypted${B}  ║${RESET}"
else
    echo -e "${B}  ║  ${Y}⚠ $PASS checks passed, $FAIL failed — see details above${B}         ║${RESET}"
fi
echo -e "${B}  ╚══════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo "  What was configured:"
echo "    • stubby    — encrypts DNS using TLS, sends to Quad9 (9.9.9.9)"
echo "    • dnsmasq   — bridges macOS system DNS (port 53) to stubby (port 5300)"
echo "    • Interfaces — every network adapter locked to 127.0.0.1"
echo "    • Firewall  — blocks any app from leaking plaintext DNS"
echo "    • Persistence — all settings survive reboots automatically"
echo ""
echo "  Your DNS privacy chain:"
echo "    Apps → macOS → dnsmasq:53 → stubby:5300 → Quad9:853 (TLS encrypted)"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "  ${Y}Troubleshooting tips:${RESET}"
    echo "    • Check stubby errors:  sudo stubby -l"
    echo "    • Check dnsmasq errors: cat /var/log/dnsmasq_err.log"
    echo "    • Check firewall:       sudo pfctl -sr"
    echo "    • Re-run this script:   sudo bash setup_dns_privacy.sh"
    echo ""
fi

echo "  Backups of your original settings: $BACKUP_DIR"
echo ""
