# Log Maintenance

Continuous passive monitoring of a network with up to 20 IoT devices generates a significant volume of log data. The `log-maintenance.sh` script runs as a daily cron job and handles compression, archiving, and retention enforcement.

## What the script does

1. **Compresses rotated Zeek logs** — Zeek rotates logs hourly and leaves timestamped files in `/opt/zeek-logs/`. The script compresses these with `gzip` and moves them to `/opt/zeek-logs/archive/`.
2. **Enforces 90-day retention** — any compressed archive file older than 90 days is deleted.
3. **Reports disk usage** — logs the total volume size, active file count, and archive file count.
4. **Verifies AdGuard logging** — confirms AdGuard's query log data directory exists.
5. **Verifies dnsmasq DHCP leases** — confirms the lease file exists and reports the active lease count.

## Installation

```bash
# Copy the script to a persistent location
sudo cp scripts/log-maintenance.sh /usr/local/bin/log-maintenance.sh
sudo chmod +x /usr/local/bin/log-maintenance.sh

# Install the daily cron job (runs at 03:00)
sudo crontab -e
# Add:
# 0 3 * * * /usr/local/bin/log-maintenance.sh >> /var/log/gateway-maintenance.log 2>&1
```

Verify the cron job is installed:

```bash
sudo crontab -l | grep log-maintenance
```

## Running manually

```bash
sudo /usr/local/bin/log-maintenance.sh
```

The script is idempotent — safe to run multiple times. It skips already-compressed files and only deletes files older than 90 days.

## Monitoring disk usage

```bash
# Current volume usage
docker exec zeek du -sh /opt/zeek-logs/
docker exec zeek du -sh /opt/zeek-logs/archive/

# Number of active log files
docker exec zeek ls /opt/zeek-logs/*.log 2>/dev/null | wc -l

# Oldest archive file
docker exec zeek ls -lt /opt/zeek-logs/archive/ | tail -1
```

As a rough estimate, a network with 10 IoT devices running moderate traffic generates approximately 50–200 MB of uncompressed Zeek logs per day. After gzip compression, this is typically 5–20 MB/day. The 90-day archive will therefore occupy roughly 0.5–2 GB in normal operation.

## Adjusting retention

The retention period is set at the top of `log-maintenance.sh`:

```bash
RETENTION_DAYS=90
```

Increasing retention requires more disk. Decreasing it may affect the ability to retrain the ML model if baseline logs from an earlier period are needed.

## AdGuard log retention

AdGuard manages its own query log retention. It is configured for 2160 hours (90 days) in `adguard/conf/AdGuardHome.yaml`:

```yaml
querylog:
  enabled: true
  interval: 2160h
```

AdGuard's retention is enforced internally by AdGuard and does not need the cron job. The `log-maintenance.sh` script verifies AdGuard is running but does not touch its log files.

## Log maintenance and the ML pipeline

The ML pipeline tails live log files using byte offsets. If a log file is compressed and removed while the pipeline is running, it will detect the inode change on the next poll and reset its read position to 0 on the new (empty) log file. This is expected and handled gracefully — no data is lost from the perspective of alerting, since log maintenance only affects completed rotated files, not the active log file the pipeline is tailing.
