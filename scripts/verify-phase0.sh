#!/usr/bin/env bash
#
# verify-phase0.sh - Phase 0 Verification
#
# Tests that the core foundation infrastructure is in place: Wi-Fi access
# point, DHCP, IP masquerade, OVS bridge, Ryu (basic switching), Zeek and
# ML Pipeline containers (placeholders), and the Zeek mirror service.
#
# Usage: sudo ./verify-phase0.sh

set -euo pipefail

BRIDGE="br0"
BRIDGE_IP="192.168.50.1"
WIFI_IFACE="wlp3s0"
WAN_IFACE="enp2s0"
DHCP_RANGE_START="192.168.50.50"
DHCP_RANGE_END="192.168.50.150"
PASS=0
FAIL=0
WARN=0

pass()    { echo "  [PASS] $1"; PASS=$((PASS + 1)); }
fail()    { echo "  [FAIL] $1"; FAIL=$((FAIL + 1)); }
warn()    { echo "  [WARN] $1"; WARN=$((WARN + 1)); }
section() { echo ""; echo "== $1 =="; }

# -- Preflight --

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root (sudo)."
    exit 1
fi

echo "Phase 0 Verification: Foundation (FR-01, FR-02, NFR-01, NFR-05, NFR-09)"
echo "$(date)"

# ── 1. hostapd ────────────────────────────────────────────────

section "FR-01 / NFR-01: Wi-Fi Access Point (hostapd)"

if systemctl is-active --quiet hostapd; then
    pass "hostapd is running"
else
    fail "hostapd is not running. Check: sudo systemctl status hostapd"
fi

if [ -f /etc/hostapd/hostapd.conf ]; then
    pass "hostapd.conf exists at /etc/hostapd/hostapd.conf"

    if grep -q "ssid=IoT-Security-AP" /etc/hostapd/hostapd.conf; then
        pass "SSID is set to IoT-Security-AP"
    else
        fail "SSID is not set to IoT-Security-AP"
    fi

    if grep -q "^wpa=2" /etc/hostapd/hostapd.conf; then
        pass "WPA2 is enabled"
    else
        fail "WPA2 not found in hostapd.conf (wpa=2)"
    fi

    if grep -q "wpa_key_mgmt=WPA-PSK" /etc/hostapd/hostapd.conf; then
        pass "WPA-PSK key management is configured"
    else
        fail "WPA-PSK not found in hostapd.conf"
    fi

    if grep -q "rsn_pairwise=CCMP" /etc/hostapd/hostapd.conf; then
        pass "CCMP (AES) encryption is configured"
    else
        warn "rsn_pairwise=CCMP not found - TKIP may be in use"
    fi

    if grep -q "ap_isolate=1" /etc/hostapd/hostapd.conf; then
        pass "ap_isolate is enabled (intra-BSS forwarding blocked)"
    else
        warn "ap_isolate not set to 1 - direct station-to-station frames may be forwarded"
    fi

    PSK_FILE=$(grep "wpa_psk_file" /etc/hostapd/hostapd.conf 2>/dev/null | cut -d= -f2 || echo "")
    if [ -n "$PSK_FILE" ] && [ -f "$PSK_FILE" ]; then
        PERMS=$(stat -c "%a" "$PSK_FILE")
        if [ "$PERMS" = "600" ]; then
            pass "PSK file $PSK_FILE exists with correct permissions (600)"
        else
            warn "PSK file exists but permissions are $PERMS (should be 600)"
        fi
    else
        warn "wpa_psk_file not found in hostapd.conf or file does not exist"
    fi
else
    fail "hostapd.conf not found at /etc/hostapd/hostapd.conf"
fi

# Check wlp3s0 is part of the OVS bridge.
if ovs-vsctl list-ports "$BRIDGE" 2>/dev/null | grep -q "$WIFI_IFACE"; then
    pass "$WIFI_IFACE is in the OVS bridge $BRIDGE"
else
    fail "$WIFI_IFACE is not in the OVS bridge $BRIDGE"
fi

# ── 2. dnsmasq ────────────────────────────────────────────────

section "FR-02: DHCP Server (dnsmasq)"

if systemctl is-active --quiet dnsmasq; then
    pass "dnsmasq is running"
else
    fail "dnsmasq is not running. Check: sudo systemctl status dnsmasq"
fi

if ss -ulnp | grep -q ":67 "; then
    pass "DHCP listener is active on port 67"
else
    fail "Nothing is listening on DHCP port 67"
fi

if [ -f /etc/dnsmasq.conf ]; then
    if grep -q "$DHCP_RANGE_START" /etc/dnsmasq.conf && grep -q "$DHCP_RANGE_END" /etc/dnsmasq.conf; then
        pass "DHCP range $DHCP_RANGE_START-$DHCP_RANGE_END is configured"
    else
        warn "DHCP range $DHCP_RANGE_START-$DHCP_RANGE_END not found in /etc/dnsmasq.conf"
    fi
else
    warn "/etc/dnsmasq.conf not found"
fi

LEASE_COUNT=$(wc -l < /var/lib/misc/dnsmasq.leases 2>/dev/null || echo "0")
pass "$LEASE_COUNT active DHCP lease(s)"

# ── 3. nftables ───────────────────────────────────────────────

section "FR-02: IP Masquerade / SNAT (nftables)"

if systemctl is-active --quiet nftables; then
    pass "nftables service is running"
else
    fail "nftables service is not running. Check: sudo systemctl status nftables"
fi

NFT_RULES=$(nft list ruleset 2>/dev/null || echo "")

if echo "$NFT_RULES" | grep -q "masquerade"; then
    pass "Masquerade (SNAT) rule is present in nftables"
else
    fail "No masquerade rule found in nftables ruleset"
fi

if echo "$NFT_RULES" | grep -q "$WAN_IFACE"; then
    pass "nftables references the WAN interface $WAN_IFACE"
else
    warn "WAN interface $WAN_IFACE not found in nftables ruleset"
fi

# Confirm IP forwarding is enabled.
FORWARD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
if [ "$FORWARD" = "1" ]; then
    pass "IP forwarding is enabled"
else
    fail "IP forwarding is disabled (/proc/sys/net/ipv4/ip_forward = 0)"
fi

# ── 4. Open vSwitch ───────────────────────────────────────────

section "FR-02 / NFR-01: Open vSwitch (br0)"

if systemctl is-active --quiet ovs-vswitchd 2>/dev/null || \
   systemctl is-active --quiet openvswitch-switch 2>/dev/null; then
    pass "OVS service is running"
else
    fail "OVS service is not running"
fi

if ovs-vsctl br-exists "$BRIDGE" 2>/dev/null; then
    pass "Bridge $BRIDGE exists"
else
    fail "Bridge $BRIDGE does not exist. Run the OVS setup script."
    echo "  Cannot check OVS further."
fi

# Confirm the bridge has an internal port with the correct IP.
BRIDGE_ADDR=$(ip addr show "$BRIDGE" 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1 || echo "")
if [ "$BRIDGE_ADDR" = "$BRIDGE_IP" ]; then
    pass "Bridge $BRIDGE has IP $BRIDGE_IP"
else
    fail "Bridge $BRIDGE does not have IP $BRIDGE_IP (found: ${BRIDGE_ADDR:-none})"
fi

# ── 5. Ryu (Basic MAC-Learning Switch) ───────────────────────

section "NFR-01 / NFR-09: Ryu SDN Controller (basic switching)"

RYU_STATE=$(docker inspect --format '{{.State.Status}}' ryu-controller 2>/dev/null || echo "not found")
if [ "$RYU_STATE" = "running" ]; then
    pass "Ryu container is running"
else
    fail "Ryu container is not running (state: $RYU_STATE). Check: docker logs ryu-controller"
fi

# Confirm OVS has a controller configured.
CONTROLLER=$(ovs-vsctl get-controller "$BRIDGE" 2>/dev/null || echo "none")
if echo "$CONTROLLER" | grep -q "6653"; then
    pass "OVS controller is set ($CONTROLLER)"
else
    fail "OVS controller is not configured on $BRIDGE"
fi

# At Phase 0 the controller may or may not be connected yet.
if ovs-vsctl show 2>/dev/null | grep -q "is_connected: true"; then
    pass "OVS is connected to the Ryu controller"
else
    warn "OVS is not yet connected to Ryu (normal if Ryu has just started)"
fi

FAIL_MODE=$(ovs-vsctl get-fail-mode "$BRIDGE" 2>/dev/null || echo "unknown")
if [ "$FAIL_MODE" = "standalone" ]; then
    pass "OVS fail mode is standalone (correct for Phase 0)"
elif [ "$FAIL_MODE" = "secure" ]; then
    warn "OVS fail mode is secure (expected standalone at Phase 0)"
else
    warn "OVS fail mode is: ${FAIL_MODE}. Expected standalone."
fi

# ── 6. Zeek Container ─────────────────────────────────────────

section "NFR-09: Zeek Container (placeholder)"

ZEEK_STATE=$(docker inspect --format '{{.State.Status}}' zeek 2>/dev/null || echo "not found")
if [ "$ZEEK_STATE" = "running" ]; then
    pass "Zeek container is running"
elif [ "$ZEEK_STATE" = "not found" ]; then
    fail "Zeek container not found. Check docker-compose.yml and run: docker compose up -d"
else
    warn "Zeek container exists but is not running (state: $ZEEK_STATE)"
fi

# ── 7. ML Pipeline Container ──────────────────────────────────

section "NFR-09: ML Pipeline Container (placeholder)"

ML_STATE=$(docker inspect --format '{{.State.Status}}' ml-pipeline 2>/dev/null || echo "not found")
if [ "$ML_STATE" = "running" ]; then
    pass "ML Pipeline container is running"
elif [ "$ML_STATE" = "not found" ]; then
    fail "ML Pipeline container not found. Check docker-compose.yml and run: docker compose up -d"
else
    warn "ML Pipeline container exists but is not running (state: $ML_STATE)"
fi

# ── 8. Docker Compose ─────────────────────────────────────────

section "NFR-05 / NFR-09: Docker Compose"

RUNNING_CONTAINERS=$(docker compose ps --services --filter "status=running" 2>/dev/null || echo "")
TOTAL_SERVICES=$(docker compose config --services 2>/dev/null | wc -l || echo "0")
RUNNING_COUNT=$(echo "$RUNNING_CONTAINERS" | grep -c "." || echo "0")

if [ "$RUNNING_COUNT" -ge 2 ]; then
    pass "$RUNNING_COUNT of $TOTAL_SERVICES services are running"
else
    fail "Only $RUNNING_COUNT of $TOTAL_SERVICES services are running"
fi

# Check that a gateway-net network exists.
if docker network ls 2>/dev/null | grep -q "gateway-net"; then
    pass "Docker network gateway-net exists"
else
    warn "Docker network gateway-net not found. Check docker-compose.yml."
fi

# ── 9. Zeek Mirror Service ────────────────────────────────────

section "FR-02: Zeek OVS Mirror (attach-zeek-mirror service)"

if systemctl is-active --quiet attach-zeek-mirror 2>/dev/null; then
    pass "attach-zeek-mirror service is running"
elif [ -f /etc/systemd/system/attach-zeek-mirror.service ]; then
    warn "attach-zeek-mirror service file exists but is not running"
else
    fail "attach-zeek-mirror service is not installed. Check the Services/zeek-mirror directory."
fi

# Check that the mirror port exists on the OVS bridge.
if ovs-vsctl list-ports "$BRIDGE" 2>/dev/null | grep -q "zeek"; then
    pass "Zeek mirror port is present on $BRIDGE"
else
    warn "No zeek mirror port found on $BRIDGE. Traffic mirroring may not be active."
fi

# ── 10. Connectivity ──────────────────────────────────────────

section "Basic Connectivity (from gateway host)"

PING_TEST=$(ping -c 2 -W 2 8.8.8.8 2>/dev/null && echo "ok" || echo "FAILED")
if [ "$PING_TEST" = "ok" ]; then
    pass "Gateway can reach the internet (ping 8.8.8.8)"
else
    warn "Gateway cannot ping 8.8.8.8 - check WAN connection and masquerade rule"
fi

echo ""
echo "  +---------------------------------------------------------+"
echo "  |  IMPORTANT: Test from an actual IoT / test device       |"
echo "  |                                                         |"
echo "  |  Connect a device to IoT-Security-AP and verify:        |"
echo "  |                                                         |"
echo "  |  1. Device associates and gets a DHCP lease in          |"
echo "  |     the 192.168.50.50-150 range                         |"
echo "  |  2. Device can resolve DNS: nslookup google.com         |"
echo "  |  3. Device can reach the internet: ping 8.8.8.8         |"
echo "  +---------------------------------------------------------+"

# ── Summary ───────────────────────────────────────────────────

echo ""
echo "============================================"
echo "  Phase 0 Verification Summary"
echo "============================================"
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo "  WARN: $WARN"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
    echo "  Some checks FAILED. Review the output above."
    exit 1
else
    echo "  All critical checks passed."
    exit 0
fi
