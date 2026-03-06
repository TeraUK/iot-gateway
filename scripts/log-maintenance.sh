#!/usr/bin/env bash
#
#
# Manages log compression and retention for all gateway components.
# Designed to run as a daily cron job on the host.
#
# All Zeek log operations are performed via docker exec, so the script
# never touches Docker's internal volume paths directly. This keeps
# things clean regardless of volume driver or mount configuration.
#
# What it does:
#   1. Compresses Zeek's rotated log files inside the container
#   2. Enforces the 90-day retention policy on Zeek archives
#   3. Reports disk usage for the Zeek log volume
#   4. Verifies AdGuard and dnsmasq logging are healthy
#
# Install:
#   sudo cp log-maintenance.sh /usr/local/bin/log-maintenance.sh
#   sudo chmod +x /usr/local/bin/log-maintenance.sh
#   sudo crontab -e
#   Add: 0 3 * * * /usr/local/bin/log-maintenance.sh >> /var/log/gateway-maintenance.log 2>&1

set -euo pipefail

ZEEK_CONTAINER="zeek"
ZEEK_LOG_PATH="/opt/zeek-logs"
ARCHIVE_SUBDIR="archive"
RETENTION_DAYS=90

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Helper: run a command inside the Zeek container.
# Returns 1 if the container is not running.
zeek_exec() {
    docker exec "$ZEEK_CONTAINER" "$@" 2>/dev/null
}

log "=== Gateway Log Maintenance Starting ==="

# ---- Preflight: check the Zeek container is running ----
ZEEK_STATE=$(docker inspect --format '{{.State.Status}}' "$ZEEK_CONTAINER" 2>/dev/null || echo "not found")
if [ "$ZEEK_STATE" != "running" ]; then
    log "WARNING: Zeek container is not running (state: $ZEEK_STATE). Skipping Zeek log maintenance."
else

    # ---- Step 1: Create archive directory inside the container ----
    zeek_exec mkdir -p "${ZEEK_LOG_PATH}/${ARCHIVE_SUBDIR}"

    # ---- Step 2: Compress rotated Zeek logs ----
    # Zeek's log rotation creates files with timestamps in the name,
    # e.g. conn.2026-03-06-12-00-00.log or conn.00:00:00-01:00:00.log.
    # Active log files have simple names like conn.log.
    # I compress the rotated ones and move them to the archive directory.
    #
    # The Zeek LTS image includes gzip, find, and sh.

    ROTATED_COUNT=$(zeek_exec sh -c "
        count=0
        # Match rotated files: anything with a date/time pattern in the name
        # that is not already compressed and is not a current active log.
        for f in ${ZEEK_LOG_PATH}/*.[0-9][0-9][0-9][0-9]-* ${ZEEK_LOG_PATH}/*.[0-9][0-9]:[0-9][0-9]:[0-9][0-9]-*; do
            [ -f \"\$f\" ] || continue
            case \"\$f\" in *.gz) continue ;; esac
            gzip \"\$f\" && count=\$((count + 1))
        done
        echo \$count
    " || echo "0")

    # Move compressed files into the archive subdirectory.
    zeek_exec sh -c "
        for f in ${ZEEK_LOG_PATH}/*.gz; do
            [ -f \"\$f\" ] || continue
            mv \"\$f\" ${ZEEK_LOG_PATH}/${ARCHIVE_SUBDIR}/
        done
    "

    log "Compressed and archived $ROTATED_COUNT rotated Zeek log files."

    # ---- Step 3: Enforce 90-day retention on archives ----
    PRUNED_COUNT=$(zeek_exec sh -c "
        find ${ZEEK_LOG_PATH}/${ARCHIVE_SUBDIR} -name '*.gz' -mtime +${RETENTION_DAYS} -print | wc -l
    " || echo "0")

    zeek_exec find "${ZEEK_LOG_PATH}/${ARCHIVE_SUBDIR}" -name '*.gz' -mtime +${RETENTION_DAYS} -delete 2>/dev/null

    log "Pruned $PRUNED_COUNT Zeek archive files older than ${RETENTION_DAYS} days."

    # ---- Step 4: Report disk usage ----
    VOLUME_USAGE=$(zeek_exec du -sh "${ZEEK_LOG_PATH}" | cut -f1 || echo "unknown")
    ACTIVE_COUNT=$(zeek_exec sh -c "find ${ZEEK_LOG_PATH} -maxdepth 1 -type f | wc -l" || echo "0")
    ARCHIVE_COUNT=$(zeek_exec sh -c "find ${ZEEK_LOG_PATH}/${ARCHIVE_SUBDIR} -type f 2>/dev/null | wc -l" || echo "0")
    ARCHIVE_SIZE=$(zeek_exec du -sh "${ZEEK_LOG_PATH}/${ARCHIVE_SUBDIR}" 2>/dev/null | cut -f1 || echo "0")

    log "Zeek log volume: ${VOLUME_USAGE} total"
    log "  Active logs: ${ACTIVE_COUNT} files"
    log "  Archived logs: ${ARCHIVE_COUNT} files (${ARCHIVE_SIZE})"
fi

# ---- Step 5: Verify AdGuard query log is healthy ----
# AdGuard manages its own query log retention (set to 2160h = 90 days
# in AdGuardHome.yaml). I just verify the container is running and
# has query log data.
AG_STATE=$(docker inspect --format '{{.State.Status}}' adguard-home 2>/dev/null || echo "not found")
if [ "$AG_STATE" = "running" ]; then
    AG_DATA=$(docker exec adguard-home ls /opt/adguardhome/work/data/ 2>/dev/null || echo "")
    if [ -n "$AG_DATA" ]; then
        log "AdGuard Home: running, query log data directory exists."
    else
        log "WARNING: AdGuard Home is running but no query log data found."
    fi
else
    log "WARNING: AdGuard Home container is not running (state: $AG_STATE)."
fi

# ---- Step 6: Check dnsmasq DHCP lease file ----
# dnsmasq writes DHCP leases to /var/lib/misc/dnsmasq.leases by default.
# This file is small and does not need rotation, but I verify it exists
# so I know DHCP assignment history is being recorded.
if [ -f "/var/lib/misc/dnsmasq.leases" ]; then
    LEASE_COUNT=$(wc -l < /var/lib/misc/dnsmasq.leases)
    log "dnsmasq lease file: ${LEASE_COUNT} active leases recorded."
else
    log "WARNING: dnsmasq lease file not found at /var/lib/misc/dnsmasq.leases"
fi

log "=== Gateway Log Maintenance Complete ==="
