# Zeek

Zeek provides the observability layer and rule-based threat detection. It runs in passive mode on a mirrored copy of all OVS bridge traffic and writes structured JSON logs to the shared `zeek-logs` volume.

## Configuration

Zeek's local policy is defined in `zeek/site/local.zeek`. This file loads protocol analysers, configures logging, and loads the IoT detection scripts.

### Protocol analysers loaded

| Protocol | Log file | Purpose |
|----------|----------|---------|
| `conn` | `conn.log` | All TCP/UDP/ICMP connection summaries |
| `dns` | `dns.log` | DNS queries and responses |
| `http` | `http.log` | HTTP transactions |
| `ssl` | `ssl.log` | TLS connections and certificate metadata |
| `dhcp` | `dhcp.log` | DHCP lease assignments (used for IP→MAC resolution) |
| `ntp` | `ntp.log` | NTP traffic |
| `ssh` | `ssh.log` | SSH connections (IoT devices should never use SSH) |
| `ftp` | `ftp.log` | FTP connections |

### Logging settings

- **Format:** JSON (all logs, via `policy/tuning/json-logs`)
- **Rotation:** Hourly (`Log::default_rotation_interval = 1 hr`)
- **DNS query case:** Preserved to enable DGA/tunnelling detection based on capitalisation patterns

### Mirror interface

Zeek listens on `zeek-eth1`, which is the container-side end of the `zeek-veth-h` veth pair. This interface receives a copy of all traffic passing through `br0`. The `zeek-mirror.service` systemd unit re-creates this pair and the OVS mirror configuration each time the Zeek container starts.

## Detection scripts

All detection scripts are in `zeek/site/iot-detection/`. They are loaded via `__load__.zeek` in dependency order.

### `alert-framework.zeek`

The shared infrastructure used by all detection scripts. Provides:

- **`emit_alert()`** - writes a structured entry to `iot_alerts.log` and, for CRITICAL alerts with `auto_isolate = T`, calls the Ryu REST API.
- **IP→MAC resolution** - maintains a `dhcp_table` populated from DHCP events, used to include MAC addresses in alert entries.
- **`is_iot_device()`** - returns true for IPs in `192.168.50.0/24` that are not the gateway (`192.168.50.1`).

**Configuration options** (override in `local.zeek`):

| Option | Default | Description |
|--------|---------|-------------|
| `IoT::auto_isolate` | `F` | Enable automatic isolation for CRITICAL alerts |
| `IoT::iot_subnet` | `192.168.50.0/24` | Monitored subnet |
| `IoT::gateway_ip` | `192.168.50.1` | Excluded from monitoring |
| `IoT::ryu_api_url` | `http://ryu:8080` | Ryu REST API endpoint |

### `detect-port-scan.zeek`

Detects reconnaissance by counting the number of distinct `(dst_ip, dst_port)` pairs a device contacts within a sliding time window.

| Threshold | Severity | Default |
|-----------|----------|---------|
| `port_scan_warning_threshold` | WARNING | 15 unique combinations |
| `port_scan_critical_threshold` | CRITICAL | 30 unique combinations |
| `port_scan_epoch` | Window duration | 60 seconds |

### `detect-dns-anomaly.zeek`

Uses Zeek's `SumStats` framework to count DNS queries per device per epoch. Also counts high-entropy domain names (Shannon entropy > threshold) as a DGA/tunnelling signal.

| Threshold | Severity | Default |
|-----------|----------|---------|
| `dns_rate_warning_threshold` | WARNING | 100 queries/epoch |
| `dns_rate_critical_threshold` | CRITICAL | 500 queries/epoch |
| `dga_warning_threshold` | WARNING | 5 high-entropy queries/epoch |
| `dns_rate_epoch` | Epoch duration | 60 seconds |

### `detect-new-destination.zeek`

Operates in two modes: `learning` (records all destinations seen) and `detecting` (flags new destinations not in the baseline). Mode is set per-device at the script level.

In learning mode, all destination IPs and domains are added to a per-device baseline table. In detecting mode, any connection to a new destination triggers an INFO alert.

Switch to detecting mode in `local.zeek`:
```zeek
redef IoT::new_dest_mode = "detecting";
```

### `detect-protocol-anomaly.zeek`

Also operates in `learning`/`detecting` modes. Tracks which destination ports each device has used. In detecting mode, new ports trigger INFO alerts. Connections to a hardcoded set of suspicious ports (SSH/22, Telnet/23, Telnet/2323, FTP/21, IRC/6667, Metasploit/4444, ADB/5555, TCP/6697 IRC over TLS) always trigger WARNING regardless of mode.

Switch to detecting mode:
```zeek
redef IoT::proto_anomaly_mode = "detecting";
```

### `detect-volume-anomaly.zeek`

Tracks total bytes sent and received per device per epoch using `SumStats`. Uses Zeek's `orig_bytes` and `resp_bytes` fields from `conn.log` entries.

| Threshold | Severity | Default |
|-----------|----------|---------|
| `volume_warning_threshold` | WARNING | 50 MB/epoch |
| `volume_critical_threshold` | CRITICAL | 500 MB/epoch |
| `volume_epoch` | Epoch duration | 60 seconds |

### `detect-known-bad.zeek`

Loads two IOC files via Zeek's `Input::add_table` framework. Files are re-read on change without requiring a Zeek restart.

| File | Content |
|------|---------|
| `zeek/site/iot-iocs/known-bad-ips.dat` | Known C2 and malware IPs (tab-separated: IP, description) |
| `zeek/site/iot-iocs/known-bad-domains.dat` | Known malicious domains (tab-separated: domain, description) |

Any connection to a known-bad IP or DNS query for a known-bad domain triggers a CRITICAL alert.

## Alert log schema (`iot_alerts.log`)

Each alert entry is a JSON object:

```json
{
  "ts": 1710000000.0,
  "severity": "CRITICAL",
  "detector": "port-scan",
  "src_ip": "192.168.50.75",
  "src_mac": "aa:bb:cc:dd:ee:ff",
  "dst_ip": "192.168.50.100",
  "dst_port": "23/tcp",
  "description": "Port scan detected: 35 unique dst pairs in 60s",
  "details": "{\"unique_pairs\": 35, \"epoch_secs\": 60}",
  "action_taken": "isolate_requested"
}
```

`action_taken` values:

| Value | Meaning |
|-------|---------|
| `logged` | INFO or WARNING; no network action taken |
| `isolate_requested` | CRITICAL; Ryu API call made |
| `dry_run` | CRITICAL but `auto_isolate = F` |
| `isolate_failed_no_mac` | CRITICAL but MAC could not be resolved from DHCP |

## Adjusting thresholds

All detection thresholds are `redef`-able in `local.zeek` without modifying the detection scripts:

```zeek
# Examples
redef IoT::port_scan_critical_threshold = 20.0;
redef IoT::dns_rate_warning_threshold   = 150.0;
redef IoT::volume_critical_threshold    = 1073741824.0;  # 1 GB
```

Restart Zeek for changes to take effect: `docker compose restart zeek`
