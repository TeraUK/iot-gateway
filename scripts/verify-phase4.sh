#!/usr/bin/env bash
#
# verify-phase4.sh - Phase 4 Verification
#
# Tests that POL-06 (detection scripts) and POL-07 (automated isolation)
# are deployed correctly and the detection infrastructure is functional.
#
# Usage: sudo ./verify-phase4.sh

set -euo pipefail

RYU_API="http://127.0.0.1:8080"
PASS=0
FAIL=0
WARN=0

pass() { echo "  [PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL + 1)); }
warn() { echo "  [WARN] $1"; WARN=$((WARN + 1)); }
section() { echo ""; echo "== $1 =="; }

# -- Preflight --

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root (sudo)."
    exit 1
fi

echo "Phase 4 Verification: Detection Scripts (POL-06) + Automated Isolation (POL-07)"
echo "$(date)"

# -- 1. Zeek Container Status --

section "Zeek Container"

ZEEK_STATE=$(docker inspect --format '{{.State.Status}}' zeek 2>/dev/null || echo "not found")
if [ "$ZEEK_STATE" = "running" ]; then
    pass "Zeek container is running"
else
    fail "Zeek container is not running (state: $ZEEK_STATE)"
    echo "  Cannot proceed without Zeek. Check: docker logs zeek"
    exit 1
fi

# Check for errors in Zeek startup logs.
ZEEK_ERRORS=$(docker logs zeek 2>&1 | tail -30 | grep -i "error" | head -5 || echo "")
if [ -z "$ZEEK_ERRORS" ]; then
    pass "No errors in recent Zeek logs"
else
    warn "Errors found in Zeek logs:"
    echo "    $ZEEK_ERRORS"
fi

# -- 2. Detection Scripts Loaded --

section "Detection Scripts"

# Check that the detection scripts directory exists inside the container.
DETECT_DIR=$(docker exec zeek ls /usr/local/zeek/share/zeek/site/iot-detection/ 2>/dev/null || echo "NOT FOUND")
if [ "$DETECT_DIR" = "NOT FOUND" ]; then
    fail "iot-detection directory not found in Zeek container"
else
    pass "iot-detection directory exists in Zeek container"

    # Check for each detection script.
    for script in alert-framework.zeek detect-port-scan.zeek detect-dns-anomaly.zeek detect-new-destination.zeek detect-protocol-anomaly.zeek detect-volume-anomaly.zeek detect-known-bad.zeek __load__.zeek; do
        if echo "$DETECT_DIR" | grep -q "$script"; then
            pass "  $script is present"
        else
            fail "  $script is MISSING"
        fi
    done
fi

# -- 3. IOC Files --

section "IOC Input Files"

IOC_DIR=$(docker exec zeek ls /usr/local/zeek/share/zeek/site/iot-iocs/ 2>/dev/null || echo "NOT FOUND")
if [ "$IOC_DIR" = "NOT FOUND" ]; then
    warn "iot-iocs directory not found (IOC matching will not work)"
else
    pass "iot-iocs directory exists"

    if echo "$IOC_DIR" | grep -q "known-bad-ips.dat"; then
        pass "  known-bad-ips.dat is present"
    else
        warn "  known-bad-ips.dat is missing"
    fi

    if echo "$IOC_DIR" | grep -q "known-bad-domains.dat"; then
        pass "  known-bad-domains.dat is present"
    else
        warn "  known-bad-domains.dat is missing"
    fi
fi

# -- 4. Alert Log --

section "Alert Log (iot_alerts.log)"

ALERT_LOG_EXISTS=$(docker exec zeek test -f /opt/zeek-logs/iot_alerts.log && echo "yes" || echo "no")
if [ "$ALERT_LOG_EXISTS" = "yes" ]; then
    ALERT_COUNT=$(docker exec zeek wc -l < /opt/zeek-logs/iot_alerts.log 2>/dev/null || echo "0")
    pass "iot_alerts.log exists ($ALERT_COUNT entries)"

    # Check it is valid JSON.
    FIRST_LINE=$(docker exec zeek head -1 /opt/zeek-logs/iot_alerts.log 2>/dev/null || echo "")
    if echo "$FIRST_LINE" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        pass "iot_alerts.log contains valid JSON"
    elif [ -n "$FIRST_LINE" ]; then
        warn "First line of iot_alerts.log may not be JSON: $FIRST_LINE"
    fi
else
    warn "iot_alerts.log does not exist yet (normal if no alerts have fired)"
fi

# -- 5. Ryu Isolation Endpoint --

section "Ryu Isolation Endpoint (POL-07)"

RYU_STATE=$(docker inspect --format '{{.State.Status}}' ryu-controller 2>/dev/null || echo "not found")
if [ "$RYU_STATE" = "running" ]; then
    pass "Ryu container is running"
else
    fail "Ryu container is not running"
fi

# Test that the isolate endpoint responds (without actually isolating).
ISOLATE_TEST=$(curl -s --max-time 5 -X POST \
    -H "Content-Type: application/json" \
    -d '{"mac": ""}' \
    "$RYU_API/policy/isolate" 2>/dev/null || echo "FAILED")
if [ "$ISOLATE_TEST" = "FAILED" ]; then
    fail "POST /policy/isolate is not responding"
else
    # Should return 400 (missing mac), which means the endpoint works.
    if echo "$ISOLATE_TEST" | grep -qi "mac"; then
        pass "POST /policy/isolate endpoint is responsive"
    else
        warn "POST /policy/isolate returned unexpected response: $ISOLATE_TEST"
    fi
fi

# Check that release endpoint also works.
RELEASE_TEST=$(curl -s --max-time 5 -X POST \
    -H "Content-Type: application/json" \
    -d '{"mac": ""}' \
    "$RYU_API/policy/release" 2>/dev/null || echo "FAILED")
if [ "$RELEASE_TEST" = "FAILED" ]; then
    fail "POST /policy/release is not responding"
else
    pass "POST /policy/release endpoint is responsive"
fi

# -- 6. OVS Mirror Port (Zeek Traffic Feed) --

section "OVS Mirror Port"

if ip link show zeek-veth-h &>/dev/null; then
    pass "Host-side veth (zeek-veth-h) exists"
else
    fail "Host-side veth (zeek-veth-h) not found (Zeek cannot see traffic)"
fi

MIRROR_EXISTS=$(ovs-vsctl list mirror 2>/dev/null | grep -c "zeek-mirror" || echo "0")
if [ "$MIRROR_EXISTS" -gt 0 ]; then
    pass "OVS mirror 'zeek-mirror' is configured"
else
    fail "OVS mirror not configured (Zeek cannot see traffic)"
fi

# -- 7. Connectivity: Zeek to Ryu --

section "Connectivity: Zeek to Ryu"

# Test that Zeek can reach Ryu via the Docker network.
ZEEK_TO_RYU=$(docker exec zeek sh -c "wget -q -O- --timeout=5 http://ryu:8080/policy/status 2>/dev/null" || echo "FAILED")
if [ "$ZEEK_TO_RYU" = "FAILED" ]; then
    # wget might not be available, try curl.
    ZEEK_TO_RYU=$(docker exec zeek sh -c "curl -s --max-time 5 http://ryu:8080/policy/status 2>/dev/null" || echo "FAILED")
fi

if [ "$ZEEK_TO_RYU" != "FAILED" ] && echo "$ZEEK_TO_RYU" | grep -q "switch_connected"; then
    pass "Zeek can reach Ryu REST API via Docker network"
else
    warn "Could not verify Zeek-to-Ryu connectivity (wget/curl may not be in the Zeek image)"
    echo "    ActiveHTTP will still work since it uses Zeek's built-in HTTP client."
fi

# -- 8. Phase 2/3 Baseline Checks --

section "Baseline: Phase 2/3 Rules Still Active"

FLOWS=$(ovs-ofctl dump-flows br0 2>/dev/null || echo "")
if echo "$FLOWS" | grep -q "priority=1.*actions=drop"; then
    pass "Default deny rule is present"
else
    fail "Default deny rule not found"
fi

if echo "$FLOWS" | grep -q "priority=150.*nw_dst=192.168.50.0"; then
    pass "Anti-lateral-movement rule is present"
else
    fail "Anti-lateral-movement rule not found"
fi

# -- Summary --

echo ""
echo "============================================"
echo "  Phase 4 Verification Summary"
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
    echo ""
    echo "  Detection scripts are loaded. Next steps:"
    echo "    1. Let the baseline detectors run in learning mode"
    echo "    2. Monitor iot_alerts.log for detections"
    echo "    3. Tune thresholds based on observed traffic"
    echo "    4. Switch to detecting mode for baseline detectors"
    echo "    5. Enable auto_isolate once detections are validated"
    exit 0
fi
