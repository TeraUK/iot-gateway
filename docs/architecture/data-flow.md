# Data Flow

This page traces how data moves between components — from raw network traffic through to an isolation action.

## Log production pipeline

```
OVS (br0)
    │  mirror copy of all bridge traffic
    ▼
Zeek (zeek-eth1)
    │  writes JSON log lines
    ▼
zeek-logs Docker volume (/opt/zeek-logs/)
    │  conn.log, dns.log, http.log, ssl.log,
    │  dhcp.log, iot_alerts.log
    ▼
ML Pipeline (reads via volume mount)
    │  writes ml_alerts.log
    ▼
zeek-logs Docker volume
```

Zeek writes to the shared `zeek-logs` volume continuously. The ML pipeline tails those files by tracking byte offsets (inode-based rotation detection). Both write their alert output to the same volume so that all alerts are in one place.

## Detection-to-isolation loop

There are two parallel paths from detection to isolation. Both converge on the Ryu REST API.

### Path 1: Zeek rule-based detection

```
Zeek captures packet
    │
    ▼
Detection script evaluates event
  (detect-port-scan, detect-dns-anomaly,
   detect-new-destination, detect-protocol-anomaly,
   detect-volume-anomaly, detect-known-bad)
    │
    ▼
alert-framework.zeek: emit_alert()
    │
    ├── severity = INFO    → write to iot_alerts.log only
    ├── severity = WARNING → write to iot_alerts.log only
    └── severity = CRITICAL, auto_isolate = T
            │
            ▼
        ActiveHTTP POST → ryu:8080/policy/isolate
            │
            ▼
        Ryu installs priority-65535 DROP rule in OVS
```

### Path 2: ML pipeline anomaly detection

```
ML Pipeline polls Zeek log files (every POLL_INTERVAL seconds)
    │
    ▼
ingestor.py: reads new log lines, tagged by type
    │
    ▼
state.py: resolves IP→MAC via dhcp.log entries,
          adds entries to per-device rolling window (5 min)
    │
    ▼
features.py: extracts 15-feature vector from window
    │
    ▼
detector.py: Isolation Forest.decision_function()
             returns anomaly score (higher = more anomalous)
    │
    ▼
pipeline.py: classify() applies rule-based checks
             then Isolation Forest thresholds
    │
    ├── severity = INFO    → write to ml_alerts.log only
    ├── severity = WARNING → write to ml_alerts.log only
    └── severity = CRITICAL, ML_AUTO_ISOLATE = true
            │
            ▼
        alerter.py: POST → ryu:8080/policy/isolate
                    (with exponential backoff retry)
            │
            ▼
        Ryu installs priority-65535 DROP rule in OVS
```

## DNS cache update loop

Domain-based allowlists in Ryu need to know the current IP addresses for permitted domains. The `dns_cache_updater` service provides this:

```
AdGuard resolves a DNS query for an IoT device
    │  (query passes through nftables DNAT → AdGuard → upstream resolver)
    ▼
Zeek observes the DNS response, logs to dns.log
    │
    ▼
dns_cache_updater.py (host systemd service)
  - tails dns.log for new entries
  - filters for domains in device profiles
  - POST → ryu:8080/policy/dns-cache
    │
    ▼
Ryu updates its internal DNS cache
  - domain → IP mapping now known
  - next Packet-In for that device+destination
    resolves correctly against the allowlist
```

## Scoring cycle timing

| Event | Interval | Configured by |
|-------|----------|---------------|
| Log file poll | 10 seconds | `POLL_INTERVAL` env var |
| ML scoring cycle | 60 seconds | `score_interval` in `thresholds.yml` |
| Zeek log rotation | 1 hour | `Log::default_rotation_interval` in `local.zeek` |
| Log compression | Daily (cron 03:00) | `log-maintenance.sh` |
| Log retention | 90 days | `log-maintenance.sh` |

## Alert log locations

| File | Written by | Content |
|------|-----------|---------|
| `/opt/zeek-logs/iot_alerts.log` | Zeek alert framework | Rule-based detections |
| `/opt/zeek-logs/ml_alerts.log` | ML pipeline alerter | Isolation Forest anomalies |
| `/opt/zeek-logs/conn.log` | Zeek | All TCP/UDP/ICMP connections |
| `/opt/zeek-logs/dns.log` | Zeek | DNS queries and responses |
| `/opt/zeek-logs/http.log` | Zeek | HTTP transactions |
| `/opt/zeek-logs/ssl.log` | Zeek | TLS connections and cert metadata |
| `/opt/zeek-logs/dhcp.log` | Zeek | DHCP leases (used for IP→MAC resolution) |
