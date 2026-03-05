#!/usr/bin/env bash
#
# health-check.sh
#
# Verifies that all components of the IoT Security Gateway are
# running and configured correctly. Run after a reboot, after
# making changes, or any time something seems off.
#
# Usage: sudo ./scripts/health-check.sh
#

set -uo pipefail

# ── Configuration ──────────────────────────────────────────────
# Edit these to match your environment.

WIFI_IFACE="wlp3s0"
WAN_IFACE="enp2s0"
BRIDGE="br0"
BRIDGE_IP="192.168.50.1"
BRIDGE_SUBNET="192.168.50.0/24"
ADGUARD_CONTAINER_IP="172.20.0.53"
RYU_API="http://127.0.0.1:8080"

# ── Counters ───────────────────────────────────────────────────

PASS=0
FAIL=0
WARN=0

pass() {
    echo "  [PASS] $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  [FAIL] $1"
    FAIL=$((FAIL + 1))
}

warn() {
    echo "  [WARN] $1"
    WARN=$((WARN + 1))
}

section() {
    echo ""
    echo "=== $1 ==="
}

# ── Preflight ─────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root (sudo)."
    exit 1
fi

echo "IoT Security Gateway Health Check"
echo "$(date)"

# ── 1. Network Interfaces ─────────────────────────────────────

section "Network Interfaces"

if ip link show "$WAN_IFACE" &>/dev/null; then
    if ip addr show "$WAN_IFACE" | grep -q "inet "; then
        WAN_IP=$(ip -4 addr show "$WAN_IFACE" | grep inet | awk '{print $2}')
        pass "$WAN_IFACE is up with IP $WAN_IP"
    else
        fail "$WAN_IFACE exists but has no IP address (DHCP not working?)"
    fi
else
    fail "$WAN_IFACE does not exist"
fi

if ip link show "$WIFI_IFACE" &>/dev/null; then
    if ip link show "$WIFI_IFACE" | grep -q "UP"; then
        pass "$WIFI_IFACE is up"
    else
        fail "$WIFI_IFACE exists but is DOWN"
    fi
else
    fail "$WIFI_IFACE does not exist"
fi

# ── 2. Open vSwitch ───────────────────────────────────────────

section "Open vSwitch"

if systemctl is-active --quiet ovs-vswitchd; then
    pass "ovs-vswitchd is running"
else
    fail "ovs-vswitchd is not running"
fi

if ovs-vsctl br-exists "$BRIDGE" 2>/dev/null; then
    pass "Bridge $BRIDGE exists"
else
    fail "Bridge $BRIDGE does not exist"
fi

if ip addr show "$BRIDGE" 2>/dev/null | grep -q "$BRIDGE_IP"; then
    pass "$BRIDGE has IP $BRIDGE_IP"
else
    fail "$BRIDGE does not have IP $BRIDGE_IP"
fi

if ovs-vsctl list-ports "$BRIDGE" 2>/dev/null | grep -q "$WIFI_IFACE"; then
    pass "$WIFI_IFACE is a port on $BRIDGE"
else
    fail "$WIFI_IFACE is not a port on $BRIDGE"
fi

FAIL_MODE=$(ovs-vsctl get-fail-mode "$BRIDGE" 2>/dev/null)
if [ -n "$FAIL_MODE" ]; then
    pass "Fail mode: $FAIL_MODE"
    if [ "$FAIL_MODE" = "standalone" ]; then
        warn "Fail mode is standalone (development). Switch to secure for production."
    fi
else
    warn "No fail mode set (defaults to standalone)"
fi

CONTROLLER=$(ovs-vsctl get-controller "$BRIDGE" 2>/dev/null)
if [ -n "$CONTROLLER" ]; then
    pass "Controller configured: $CONTROLLER"
    if ovs-vsctl show | grep -q "is_connected: true"; then
        pass "Controller connection: connected"
    else
        fail "Controller connection: not connected"
    fi
else
    warn "No OpenFlow controller configured"
fi

# ── 3. hostapd ─────────────────────────────────────────────────

section "hostapd"

if systemctl is-active --quiet hostapd; then
    pass "hostapd is running"
else
    fail "hostapd is not running"
fi

if [ -f /etc/hostapd/hostapd.conf ]; then
    pass "hostapd.conf exists"
    if grep -q "wpa_psk_file" /etc/hostapd/hostapd.conf; then
        PSK_FILE=$(grep "wpa_psk_file" /etc/hostapd/hostapd.conf | cut -d= -f2)
        if [ -f "$PSK_FILE" ]; then
            PERMS=$(stat -c "%a" "$PSK_FILE")
            if [ "$PERMS" = "600" ]; then
                pass "PSK file exists with correct permissions (600)"
            else
                warn "PSK file exists but permissions are $PERMS (should be 600)"
            fi
        else
            fail "PSK file $PSK_FILE does not exist"
        fi
    elif grep -q "wpa_passphrase" /etc/hostapd/hostapd.conf; then
        warn "Using wpa_passphrase in config file (consider wpa_psk_file instead)"
    fi
else
    fail "hostapd.conf not found at /etc/hostapd/hostapd.conf"
fi

CONNECTED_CLIENTS=$(iw dev "$WIFI_IFACE" station dump 2>/dev/null | grep -c "Station")
pass "$CONNECTED_CLIENTS WiFi client(s) currently connected"

# ── 4. dnsmasq ─────────────────────────────────────────────────

section "dnsmasq"

if systemctl is-active --quiet dnsmasq; then
    pass "dnsmasq is running"
else
    fail "dnsmasq is not running"
fi

if ss -ulnp | grep -q ":67 "; then
    pass "DHCP listener active on port 67"
else
    fail "Nothing listening on DHCP port 67"
fi

if grep -q "^port=0" /etc/dnsmasq.conf 2>/dev/null; then
    pass "dnsmasq DNS is disabled (port=0) as expected"
else
    warn "dnsmasq DNS may still be active (port=0 not found in config)"
fi

LEASE_COUNT=$(wc -l < /var/lib/misc/dnsmasq.leases 2>/dev/null || echo "0")
pass "$LEASE_COUNT active DHCP lease(s)"

# ── 5. IP Forwarding and nftables ─────────────────────────────

section "IP Forwarding and nftables"

IP_FWD=$(cat /proc/sys/net/ipv4/ip_forward)
if [ "$IP_FWD" = "1" ]; then
    pass "IPv4 forwarding is enabled"
else
    fail "IPv4 forwarding is disabled"
fi

if systemctl is-active --quiet nftables; then
    pass "nftables service is active"
else
    warn "nftables service is not active (rules may still be loaded)"
fi

NFT_RULESET=$(nft list ruleset 2>/dev/null || true)

if echo "$NFT_RULESET" | grep -q "masquerade"; then
    pass "NAT masquerade rule is loaded"
else
    fail "NAT masquerade rule not found"
fi

if echo "$NFT_RULESET" | grep -q "dnat to $ADGUARD_CONTAINER_IP"; then
    pass "DNS DNAT rule is loaded (redirects to $ADGUARD_CONTAINER_IP)"
else
    fail "DNS DNAT rule not found (devices can bypass AdGuard)"
fi

# ── 6. Docker ──────────────────────────────────────────────────

section "Docker"

if systemctl is-active --quiet docker; then
    pass "Docker engine is running"
else
    fail "Docker engine is not running"
fi

# ── 7. Ryu Controller ─────────────────────────────────────────

section "Ryu SDN Controller"

RYU_STATE=$(docker inspect --format '{{.State.Status}}' ryu-controller 2>/dev/null)
if [ "$RYU_STATE" = "running" ]; then
    pass "Container is running"
else
    fail "Container is not running (state: ${RYU_STATE:-not found})"
fi

if curl -s --max-time 3 "$RYU_API/stats/switches" &>/dev/null; then
    SWITCHES=$(curl -s --max-time 3 "$RYU_API/stats/switches")
    pass "REST API is responding"
    if [ "$SWITCHES" != "[]" ]; then
        pass "OVS switch connected to Ryu (dpid: $SWITCHES)"
    else
        warn "REST API is up but no switches connected"
    fi
else
    fail "REST API is not responding on $RYU_API"
fi

# ── 8. AdGuard Home ───────────────────────────────────────────

section "AdGuard Home"

AG_STATE=$(docker inspect --format '{{.State.Status}}' adguard-home 2>/dev/null)
if [ "$AG_STATE" = "running" ]; then
    pass "Container is running"
else
    fail "Container is not running (state: ${AG_STATE:-not found})"
fi

AG_IP=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' adguard-home 2>/dev/null)
if [ "$AG_IP" = "$ADGUARD_CONTAINER_IP" ]; then
    pass "Container IP is $AG_IP (matches DNAT target)"
else
    fail "Container IP is $AG_IP (expected $ADGUARD_CONTAINER_IP)"
fi

if ss -ulnp | grep -q "${BRIDGE_IP}:53"; then
    pass "DNS listener active on ${BRIDGE_IP}:53"
elif ss -ulnp | grep -q ":53 "; then
    pass "DNS listener active on port 53"
else
    fail "Nothing listening on DNS port 53"
fi

# ── 9. Zeek ────────────────────────────────────────────────────

section "Zeek"

ZEEK_STATE=$(docker inspect --format '{{.State.Status}}' zeek 2>/dev/null)
if [ "$ZEEK_STATE" = "running" ]; then
    pass "Container is running"
else
    fail "Container is not running (state: ${ZEEK_STATE:-not found})"
fi

if docker exec zeek ls /sys/class/net/zeek-eth1 &>/dev/null; then
    pass "Mirror interface zeek-eth1 is present in container"
else
    fail "Mirror interface zeek-eth1 not found in container"
fi

if ip link show zeek-veth-h &>/dev/null; then
    pass "Host-side veth (zeek-veth-h) exists"
else
    fail "Host-side veth (zeek-veth-h) does not exist"
fi

if ovs-vsctl list-ports "$BRIDGE" 2>/dev/null | grep -q "zeek-veth-h"; then
    pass "zeek-veth-h is a port on $BRIDGE"
else
    fail "zeek-veth-h is not a port on $BRIDGE"
fi

MIRROR_EXISTS=$(ovs-vsctl list mirror 2>/dev/null | grep -c "zeek-mirror")
if [ "$MIRROR_EXISTS" -gt 0 ]; then
    pass "OVS mirror 'zeek-mirror' is configured"
else
    fail "OVS mirror 'zeek-mirror' not found"
fi

ZEEK_LOGS=$(docker exec zeek ls /opt/zeek-logs/ 2>/dev/null | head -5)
if [ -n "$ZEEK_LOGS" ]; then
    LOG_COUNT=$(docker exec zeek ls /opt/zeek-logs/ 2>/dev/null | wc -l)
    pass "Zeek is writing logs ($LOG_COUNT files in current/)"
else
    warn "No log files in /opt/zeek-logs/ yet (may need traffic to generate)"
fi

# ── 10. Zeek Mirror Service ───────────────────────────────────

section "Zeek Mirror Service"

if systemctl is-active --quiet zeek-mirror; then
    pass "zeek-mirror.service is running (watching for container events)"
else
    fail "zeek-mirror.service is not running"
fi

if systemctl is-enabled --quiet zeek-mirror; then
    pass "zeek-mirror.service is enabled (will start on boot)"
else
    fail "zeek-mirror.service is not enabled"
fi

# ── 11. ML Pipeline ───────────────────────────────────────────

section "ML Pipeline"

ML_STATE=$(docker inspect --format '{{.State.Status}}' ml-pipeline 2>/dev/null)
if [ "$ML_STATE" = "running" ]; then
    pass "Container is running"
else
    fail "Container is not running (state: ${ML_STATE:-not found})"
fi

if docker exec ml-pipeline ls /opt/zeek-logs &>/dev/null; then
    pass "Zeek logs volume is mounted"
else
    fail "Zeek logs volume is not accessible"
fi

# ── 12. Internet Connectivity ─────────────────────────────────

section "Internet Connectivity"

if ping -c 1 -W 3 8.8.8.8 &>/dev/null; then
    pass "Host can reach 8.8.8.8 (internet is reachable)"
else
    fail "Host cannot reach 8.8.8.8 (no internet)"
fi

if ping -c 1 -W 3 google.com &>/dev/null; then
    pass "Host can resolve and reach google.com (DNS working)"
else
    fail "Host cannot resolve google.com (DNS issue)"
fi

# ── Summary ────────────────────────────────────────────────────

echo ""
echo "==========================================="
echo " Health Check Summary"
echo "==========================================="
echo "  PASS: $PASS"
echo "  WARN: $WARN"
echo "  FAIL: $FAIL"
echo ""

if [ "$FAIL" -eq 0 ] && [ "$WARN" -eq 0 ]; then
    echo "  All checks passed. Gateway is fully operational."
elif [ "$FAIL" -eq 0 ]; then
    echo "  All critical checks passed. Review warnings above."
else
    echo "  $FAIL check(s) failed. Review the output above."
fi

echo ""
exit "$FAIL"
