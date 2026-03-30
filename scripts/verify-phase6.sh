#!/usr/bin/env bash
#
# verify-phase6.sh - Phase 6 Verification
#
# Tests that FR-09 (ML anomaly detection) and FR-06 (automated isolation
# via ML) are operational: the ML pipeline container is running a functional
# pipeline (not a placeholder), at least one trained model is present,
# structured alerts are being written to ml_alerts.log, and the Ryu
# integration is reachable from the container.
#
# Usage: sudo ./verify-phase6.sh

set -euo pipefail

RYU_API="http://127.0.0.1:8080"
MODELS_DIR="./ml-pipeline/models"
ZEEK_LOG_DIR="./zeek/logs"
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

echo "Phase 6 Verification: ML-Based Anomaly Detection (FR-09) + Auto-Isolation (FR-06)"
echo "$(date)"

# ── 1. ML Pipeline Container ──────────────────────────────────

section "FR-09: ML Pipeline Container"

ML_STATE=$(docker inspect --format '{{.State.Status}}' ml-pipeline 2>/dev/null || echo "not found")
if [ "$ML_STATE" = "running" ]; then
    pass "ML Pipeline container is running"
else
    fail "ML Pipeline container is not running (state: $ML_STATE)"
    echo "  Cannot proceed without the ML pipeline. Check: docker logs ml-pipeline"
    exit 1
fi

# Check that the pipeline is running the real pipeline, not the placeholder.
ML_LOGS=$(docker logs ml-pipeline 2>&1 | tail -50)
if echo "$ML_LOGS" | grep -q "Pipeline started\|Starting pipeline\|poll interval\|Loaded.*model\|No models found"; then
    pass "ML pipeline script is running (functional pipeline detected)"
elif echo "$ML_LOGS" | grep -q "placeholder\|TODO\|not implemented"; then
    fail "ML pipeline container appears to be running the placeholder script"
    echo "    Replace the placeholder with pipeline.py and rebuild the image."
else
    warn "Could not confirm pipeline status from logs - review manually: docker logs ml-pipeline"
fi

# Check for errors in recent ML pipeline logs.
ML_ERRORS=$(docker logs ml-pipeline 2>&1 | tail -50 | grep -i "^ERROR\|^CRITICAL" | head -5 || echo "")
if [ -z "$ML_ERRORS" ]; then
    pass "No ERROR or CRITICAL entries in recent ML pipeline logs"
else
    warn "Errors found in ML pipeline logs:"
    echo "$ML_ERRORS" | sed 's/^/    /'
fi

# ── 2. Trained Models ─────────────────────────────────────────

section "FR-09: Trained Isolation Forest Models"

if [ -d "$MODELS_DIR" ]; then
    pass "Models directory exists ($MODELS_DIR)"

    MODEL_COUNT=$(find "$MODELS_DIR" -name "*.joblib" 2>/dev/null | wc -l)
    if [ "$MODEL_COUNT" -gt 0 ]; then
        pass "$MODEL_COUNT .joblib model file(s) found"

        # Check for the fleet model specifically.
        if find "$MODELS_DIR" -name "_fleet.joblib" 2>/dev/null | grep -q .; then
            pass "Fleet model (_fleet.joblib) is present"
        else
            warn "No fleet model found (_fleet.joblib). New devices will not be scored until trained."
        fi

        # Report per-device models.
        DEVICE_MODELS=$(find "$MODELS_DIR" -name "*.joblib" ! -name "_fleet.joblib" 2>/dev/null | wc -l)
        pass "$DEVICE_MODELS per-device model(s) found"
    else
        fail "No .joblib model files found in $MODELS_DIR"
        echo "    Run train.py first: python3 ml-pipeline/train/train.py --log-dir <zeek-logs> --output-dir $MODELS_DIR"
    fi
else
    fail "Models directory not found at $MODELS_DIR"
    echo "    Run train.py to create models, or check the MODELS_DIR path in docker-compose.yml"
fi

# Also check inside the container that models are accessible.
ML_MODELS_CONTAINER=$(docker exec ml-pipeline find /opt/ml-pipeline/models -name "*.joblib" 2>/dev/null | wc -l || echo "0")
if [ "$ML_MODELS_CONTAINER" -gt 0 ]; then
    pass "$ML_MODELS_CONTAINER model(s) visible inside the container"
else
    warn "No models visible inside the container at /opt/ml-pipeline/models"
    echo "    Check the models bind mount in docker-compose.yml"
fi

# ── 3. ML Alerts Log ──────────────────────────────────────────

section "FR-09: ML Alerts Log (ml_alerts.log)"

ML_ALERT_LOG=$(find "$ZEEK_LOG_DIR" -name "ml_alerts.log" 2>/dev/null | head -1 || echo "")
if [ -n "$ML_ALERT_LOG" ]; then
    pass "ml_alerts.log found at $ML_ALERT_LOG"

    ALERT_COUNT=$(wc -l < "$ML_ALERT_LOG" 2>/dev/null || echo "0")
    pass "$ALERT_COUNT alert(s) written to ml_alerts.log"

    # Validate that entries are JSON.
    LAST_LINE=$(tail -1 "$ML_ALERT_LOG" 2>/dev/null || echo "")
    if echo "$LAST_LINE" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        pass "Last ml_alerts.log entry is valid JSON"
    elif [ -z "$LAST_LINE" ]; then
        warn "ml_alerts.log exists but is empty (no alerts generated yet - normal if the pipeline has just started)"
    else
        warn "Last ml_alerts.log entry does not appear to be valid JSON"
    fi
else
    warn "ml_alerts.log not found in $ZEEK_LOG_DIR"
    echo "    The pipeline writes this file once it produces its first alert."
    echo "    This is expected if the pipeline has just started or no anomalies have been detected."
fi

# ── 4. Scoring Activity ───────────────────────────────────────

section "FR-09: Pipeline Scoring Activity"

# Check that the pipeline is producing scoring log output regularly.
SCORING_LINES=$(docker logs --since 5m ml-pipeline 2>&1 | grep -c "Scored\|scoring\|anomaly\|poll" || echo "0")
if [ "$SCORING_LINES" -gt 0 ]; then
    pass "Pipeline has produced $SCORING_LINES scoring-related log lines in the last 5 minutes"
else
    warn "No scoring activity detected in the last 5 minutes"
    echo "    The pipeline may be waiting for Zeek log entries, or no devices are active."
fi

# ── 5. Ryu Integration (FR-06) ────────────────────────────────

section "FR-06: Ryu REST API Reachability from ML Pipeline"

# Confirm Ryu is up and responding.
STATUS_RESPONSE=$(curl -s --max-time 5 "$RYU_API/policy/status" 2>/dev/null || echo "FAILED")
if [ "$STATUS_RESPONSE" != "FAILED" ]; then
    pass "Ryu policy REST API is responding on the host"
else
    fail "Ryu policy REST API is not responding at $RYU_API"
    echo "    Check: docker logs ryu-controller"
fi

# Check that the ML pipeline container can reach Ryu.
RYU_FROM_ML=$(docker exec ml-pipeline curl -s --max-time 5 "http://ryu-controller:8080/policy/status" 2>/dev/null && echo "ok" || echo "FAILED")
if [ "$RYU_FROM_ML" = "ok" ]; then
    pass "Ryu REST API is reachable from the ML pipeline container (http://ryu-controller:8080)"
else
    fail "Ryu REST API is NOT reachable from the ML pipeline container"
    echo "    Check that ryu-controller and ml-pipeline are on the same Docker network (gateway-net)"
fi

# Check whether ML_AUTO_ISOLATE is configured in the container environment.
ML_AUTO_ISOLATE=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' ml-pipeline 2>/dev/null \
    | grep "ML_AUTO_ISOLATE" | cut -d= -f2 || echo "")
if [ "$ML_AUTO_ISOLATE" = "true" ]; then
    pass "ML_AUTO_ISOLATE is enabled - CRITICAL alerts will trigger automatic isolation"
elif [ "$ML_AUTO_ISOLATE" = "false" ] || [ -z "$ML_AUTO_ISOLATE" ]; then
    warn "ML_AUTO_ISOLATE is disabled or not set - CRITICAL alerts will be logged as dry_run only"
    echo "    To enable: set ML_AUTO_ISOLATE=true in docker-compose.yml and restart the container"
else
    warn "ML_AUTO_ISOLATE is set to an unexpected value: $ML_AUTO_ISOLATE"
fi

# ── 6. Isolation Endpoint ─────────────────────────────────────

section "FR-06: Ryu Isolation Endpoint"

ISOLATE_RESPONSE=$(curl -s --max-time 5 -X POST \
    -H "Content-Type: application/json" \
    -d '{"mac":"00:00:00:00:00:00"}' \
    "$RYU_API/policy/isolate" 2>/dev/null || echo "FAILED")

if [ "$ISOLATE_RESPONSE" = "FAILED" ]; then
    fail "POST /policy/isolate is not responding"
else
    # A response (even an error about an unknown MAC) confirms the endpoint is live.
    pass "POST /policy/isolate endpoint is responding"
fi

RELEASE_RESPONSE=$(curl -s --max-time 5 -X POST \
    -H "Content-Type: application/json" \
    -d '{"mac":"00:00:00:00:00:00"}' \
    "$RYU_API/policy/release" 2>/dev/null || echo "FAILED")

if [ "$RELEASE_RESPONSE" = "FAILED" ]; then
    fail "POST /policy/release is not responding"
else
    pass "POST /policy/release endpoint is responding"
fi

# ── 7. Zeek Logs Available ────────────────────────────────────

section "FR-09: Zeek Logs (ML pipeline input)"

ZEEK_STATE=$(docker inspect --format '{{.State.Status}}' zeek 2>/dev/null || echo "not found")
if [ "$ZEEK_STATE" = "running" ]; then
    pass "Zeek container is running (producing log input for the ML pipeline)"
else
    fail "Zeek container is not running (state: $ZEEK_STATE) - ML pipeline will have no input"
fi

# Check that the log directory shared between Zeek and the ML pipeline has conn.log.
if [ -d "$ZEEK_LOG_DIR" ]; then
    CONN_LOG=$(find "$ZEEK_LOG_DIR" -name "conn.log" 2>/dev/null | head -1 || echo "")
    if [ -n "$CONN_LOG" ]; then
        pass "conn.log is present in the shared log directory"
    else
        warn "conn.log not found in $ZEEK_LOG_DIR - Zeek may not have produced logs yet"
    fi
else
    warn "Zeek log directory $ZEEK_LOG_DIR not found"
fi

# ── Summary ───────────────────────────────────────────────────

echo ""
echo "============================================"
echo "  Phase 6 Verification Summary"
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
