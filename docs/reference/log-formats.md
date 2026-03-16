# Log Formats

All Zeek logs are written as JSON (one object per line). The ML pipeline and alert framework follow the same convention so that all log sources can be parsed uniformly.

## Zeek log directory layout

```
/opt/zeek-logs/
├── conn.log          ← Active connection summaries (current hour)
├── dns.log           ← Active DNS queries/responses
├── http.log          ← Active HTTP transactions
├── ssl.log           ← Active TLS connections
├── dhcp.log          ← Active DHCP lease events
├── iot_alerts.log    ← Zeek detection script alerts
├── ml_alerts.log     ← ML pipeline alerts
└── archive/          ← Compressed rotated logs (.log.gz)
    ├── conn.2026-03-15-11-00-00.log.gz
    └── ...
```

Log files in the root are the current (active) files. Rotated files are timestamped by Zeek and moved to `archive/` by the daily `log-maintenance.sh` cron job after compression.

---

## `conn.log` — connection summaries

Key fields used by the ML pipeline:

| Field | Type | Description |
|-------|------|-------------|
| `ts` | float | Connection start time (UNIX epoch) |
| `id.orig_h` | string | Source IP (IoT device) |
| `id.orig_p` | int | Source port |
| `id.resp_h` | string | Destination IP |
| `id.resp_p` | int | Destination port |
| `proto` | string | `tcp`, `udp`, `icmp` |
| `duration` | float | Connection duration (seconds) |
| `orig_bytes` | int | Bytes sent by originator |
| `resp_bytes` | int | Bytes sent by responder |
| `conn_state` | string | Final connection state (see below) |

**Connection state values relevant to anomaly detection:**

| State | Meaning | Significance |
|-------|---------|--------------|
| `S0` | SYN sent, no response | Port is closed or filtered |
| `REJ` | RST received | Port actively refused |
| `SF` | Normal connection teardown | Normal |
| `S1`/`S2`/`S3` | Partial teardown | Can indicate scanning |

A high proportion of `S0` or `REJ` connections (`failed_conn_rate`) is a strong port scanning signal.

---

## `dns.log` — DNS queries and responses

Key fields used by the ML pipeline:

| Field | Type | Description |
|-------|------|-------------|
| `ts` | float | Query timestamp |
| `id.orig_h` | string | Querying device IP |
| `query` | string | Domain name queried (original case preserved) |
| `qtype_name` | string | Query type (`A`, `AAAA`, `MX`, etc.) |
| `rcode_name` | string | Response code (`NOERROR`, `NXDOMAIN`, etc.) |
| `answers` | array | Returned IP addresses |

---

## `dhcp.log` — DHCP events

Used exclusively for IP→MAC resolution by both Zeek and the ML pipeline.

| Field | Type | Description |
|-------|------|-------------|
| `ts` | float | Event timestamp |
| `mac` | string | Client MAC address |
| `assigned_addr` | string | IP assigned to the client |
| `client_addr` | string | IP the client requested (may differ from assigned) |
| `hostname` | string | Client-supplied hostname (if provided) |

---

## `iot_alerts.log` — Zeek detection alerts

Written by `alert-framework.zeek`. One JSON object per line.

| Field | Type | Description |
|-------|------|-------------|
| `ts` | float | Alert timestamp |
| `severity` | string | `INFO`, `WARNING`, or `CRITICAL` |
| `detector` | string | Name of the detection script |
| `src_ip` | string | Flagged device IP |
| `src_mac` | string | Flagged device MAC (or `"unknown"` if not in DHCP table) |
| `dst_ip` | string | Destination IP (if applicable) |
| `dst_port` | string | Destination port (e.g., `"443/tcp"`) |
| `description` | string | Human-readable summary |
| `details` | string | JSON-encoded detector-specific metadata |
| `action_taken` | string | `logged`, `isolate_requested`, `dry_run`, `isolate_failed_no_mac` |

**Detector names:** `port-scan`, `dns-rate`, `dns-dga`, `new-destination`, `protocol-anomaly`, `volume-anomaly`, `known-bad-ip`, `known-bad-domain`

---

## `ml_alerts.log` — ML pipeline alerts

Written by `alerter.py`. Same schema as `iot_alerts.log` for uniform parsing.

| Field | Type | Description |
|-------|------|-------------|
| `ts` | string | ISO-8601 timestamp |
| `severity` | string | `INFO`, `WARNING`, or `CRITICAL` |
| `detector` | string | Always `"ml-isolation-forest"` |
| `src_ip` | string | Flagged device IP |
| `src_mac` | string | Flagged device MAC (or `"unknown"`) |
| `description` | string | Human-readable summary including trigger and values |
| `details` | string | JSON-encoded dict with `trigger`, raw feature values, `anomaly_score`, and `model_type` |
| `action_taken` | string | `logged`, `isolate_requested`, `dry_run`, `isolate_failed` |

`model_type` in `details` is either `"per-device"` or `"fleet"`, indicating which model produced the score.

---

## Parsing alerts from the command line

```bash
# Show all CRITICAL alerts from both sources
cat /opt/zeek-logs/iot_alerts.log /opt/zeek-logs/ml_alerts.log \
  | python3 -c "
import sys, json
for line in sys.stdin:
    e = json.loads(line)
    if e['severity'] == 'CRITICAL':
        print(e['ts'], e['src_mac'], e['description'][:80])
"

# Show isolated devices (isolate_requested)
grep '"action_taken": "isolate_requested"' /opt/zeek-logs/iot_alerts.log \
  | python3 -c "import sys,json; [print(json.loads(l)['src_mac'], json.loads(l)['ts']) for l in sys.stdin]"
```
