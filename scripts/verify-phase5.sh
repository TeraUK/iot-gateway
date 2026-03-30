#!/usr/bin/env bash
#
# verify-phase5.sh - Phase 5 Verification
#
# Tests that NFR-05 (reliability and resilience) hardening is in place:
# OVS secure fail mode, Docker restart policies, systemd service overrides
# for hostapd and dnsmasq, and the presence of the health check script.
#
# Usage: sudo ./verify-phase5.sh

set -euo pipefail

BRIDGE="br0"
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

echo "Phase 5 Verification: Resilience and Hardening (NFR-05)"
echo "$(date)"

# ── 1. OVS Secure Fail Mode ───────────────────────────────────

section "NFR-05: OVS Secure Fail Mode"

FAIL_MODE=$(ovs-vsctl get-fail-mode "$BRIDGE" 2>/dev/null || echo "unknown")
if [ "$FAIL_MODE" = "secure" ]; then
    pass "OVS fail mode is secure"
elif [ "$FAIL_MODE" = "standalone" ]; then
    fail "OVS fail mode is still standalone. Switch to secure with:"
    echo "    sudo ovs-vsctl set-fail-mode $BRIDGE secure"
    echo "    WARNING: Only do this once Ryu has been running reliably."
else
    fail "OVS fail mode is unexpected: $FAIL_MODE"
fi

# Confirm Ryu is connected - in secure mode a disconnected controller
# causes all traffic to be dropped, so this is critical to verify.
if ovs-vsctl show 2>/dev/null | grep -q "is_connected: true"; then
    pass "OVS is connected to the Ryu controller"
else
    fail "OVS is NOT connected to Ryu. In secure fail mode this will drop all traffic."
    echo "    Check: docker ps | grep ryu && docker logs ryu-controller"
fi

CONTROLLER=$(ovs-vsctl get-controller "$BRIDGE" 2>/dev/null || echo "none")
if echo "$CONTROLLER" | grep -q "6653"; then
    pass "OVS controller is configured ($CONTROLLER)"
else
    fail "OVS controller is not configured on $BRIDGE"
fi

# ── 2. Docker Restart Policies ────────────────────────────────

section "NFR-05: Docker Container Restart Policies"

EXPECTED_POLICY="unless-stopped"

for SERVICE in ryu-controller zeek ml-pipeline adguard-home; do
    POLICY=$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$SERVICE" 2>/dev/null || echo "not found")
    if [ "$POLICY" = "$EXPECTED_POLICY" ]; then
        pass "$SERVICE restart policy: $POLICY"
    elif [ "$POLICY" = "not found" ]; then
        warn "$SERVICE container not found - cannot check restart policy"
    else
        fail "$SERVICE restart policy is '$POLICY' (expected '$EXPECTED_POLICY')"
        echo "    Update in docker-compose.yml: restart: unless-stopped"
    fi
done

# ── 3. Systemd Service Overrides ──────────────────────────────

section "NFR-05: Systemd Service Overrides (startup order)"

# hostapd override.
HOSTAPD_OVERRIDE="/etc/systemd/system/hostapd.service.d/override.conf"
if [ -f "$HOSTAPD_OVERRIDE" ]; then
    pass "hostapd override.conf exists at $HOSTAPD_OVERRIDE"

    if grep -q "After=" "$HOSTAPD_OVERRIDE" || grep -q "Requires=" "$HOSTAPD_OVERRIDE"; then
        pass "hostapd override.conf contains startup ordering directives"
    else
        warn "hostapd override.conf exists but has no After= or Requires= directives"
    fi
else
    fail "hostapd override.conf not found at $HOSTAPD_OVERRIDE"
    echo "    Create /etc/systemd/system/hostapd.service.d/ and add override.conf"
fi

# dnsmasq override.
DNSMASQ_OVERRIDE="/etc/systemd/system/dnsmasq.service.d/override.conf"
if [ -f "$DNSMASQ_OVERRIDE" ]; then
    pass "dnsmasq override.conf exists at $DNSMASQ_OVERRIDE"

    if grep -q "After=" "$DNSMASQ_OVERRIDE" || grep -q "Requires=" "$DNSMASQ_OVERRIDE"; then
        pass "dnsmasq override.conf contains startup ordering directives"
    else
        warn "dnsmasq override.conf exists but has no After= or Requires= directives"
    fi
else
    fail "dnsmasq override.conf not found at $DNSMASQ_OVERRIDE"
    echo "    Create /etc/systemd/system/dnsmasq.service.d/ and add override.conf"
fi

# Confirm systemd has loaded the overrides.
if systemctl show hostapd --property=After 2>/dev/null | grep -q "docker\|ovs"; then
    pass "systemd has loaded the hostapd override (docker/ovs dependency visible)"
else
    warn "hostapd override may not have been reloaded. Run: sudo systemctl daemon-reload"
fi

# ── 4. Health Check Script ────────────────────────────────────

section "NFR-05: Health Check Script"

HEALTH_SCRIPT="scripts/health-check.sh"
if [ -f "$HEALTH_SCRIPT" ]; then
    pass "$HEALTH_SCRIPT exists"

    if [ -x "$HEALTH_SCRIPT" ]; then
        pass "$HEALTH_SCRIPT is executable"
    else
        fail "$HEALTH_SCRIPT is not executable. Run: chmod +x $HEALTH_SCRIPT"
    fi
elif [ -f "/usr/local/bin/health-check.sh" ]; then
    pass "health-check.sh found at /usr/local/bin/health-check.sh"
else
    fail "health-check.sh not found. It should be at scripts/health-check.sh"
fi

# ── 5. All Containers Running ─────────────────────────────────

section "NFR-05: All Containers Running"

for SERVICE in ryu-controller zeek ml-pipeline adguard-home; do
    STATE=$(docker inspect --format '{{.State.Status}}' "$SERVICE" 2>/dev/null || echo "not found")
    if [ "$STATE" = "running" ]; then
        pass "$SERVICE is running"
    elif [ "$STATE" = "not found" ]; then
        warn "$SERVICE container not found"
    else
        fail "$SERVICE is not running (state: $STATE)"
    fi
done

# ── 6. All Systemd Services Running ──────────────────────────

section "NFR-05: Host Services"

for SVC in hostapd dnsmasq nftables; do
    if systemctl is-active --quiet "$SVC" 2>/dev/null; then
        pass "$SVC is active"
    else
        fail "$SVC is not active. Check: sudo systemctl status $SVC"
    fi
done

if systemctl is-active --quiet attach-zeek-mirror 2>/dev/null; then
    pass "attach-zeek-mirror is active"
else
    fail "attach-zeek-mirror is not active. Run: sudo systemctl start attach-zeek-mirror"
fi

if systemctl is-active --quiet dns-cache-updater 2>/dev/null; then
    pass "dns-cache-updater is active"
elif [ -f /etc/systemd/system/dns-cache-updater.service ]; then
    warn "dns-cache-updater service file exists but is not running"
else
    warn "dns-cache-updater service is not installed (Phase 3 may not be complete)"
fi

# ── 7. Connectivity Check ─────────────────────────────────────

section "Connectivity"

PING_TEST=$(ping -c 2 -W 2 8.8.8.8 2>/dev/null && echo "ok" || echo "FAILED")
if [ "$PING_TEST" = "ok" ]; then
    pass "Gateway can reach the internet (ping 8.8.8.8)"
else
    warn "Gateway cannot ping 8.8.8.8 - check WAN connection"
fi

RYU_API="http://127.0.0.1:8080"
STATUS_RESPONSE=$(curl -s --max-time 5 "$RYU_API/policy/status" 2>/dev/null || echo "FAILED")
if [ "$STATUS_RESPONSE" != "FAILED" ]; then
    pass "Ryu policy REST API is responding"
else
    fail "Ryu policy REST API is not responding at $RYU_API"
fi

# ── Summary ───────────────────────────────────────────────────

echo ""
echo "============================================"
echo "  Phase 5 Verification Summary"
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
