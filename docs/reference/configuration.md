# Configuration Reference

## `ryu/config/device_profiles.json`

Per-device destination allowlists. Loaded by the Ryu policy application at startup and reloadable at runtime via `POST /policy/allowlists/reload`.

```json
{
  "<mac_address>": {
    "name": "<human-readable device name>",
    "allowed_domains": [
      "<fully-qualified domain name>"
    ],
    "allowed_cidrs": [
      "<ip>/<prefix-length>"
    ]
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Display name used in logs and the API |
| `allowed_domains` | array of strings | No | Domains the device is permitted to contact. Resolved to IPs via the DNS cache. |
| `allowed_cidrs` | array of strings | No | IP ranges the device is permitted to contact directly (e.g., for CDN destinations not reachable via a single domain) |

**Notes:**

- MAC addresses must be lowercase, colon-separated (`aa:bb:cc:dd:ee:ff`).
- Domain-based rules rely on the DNS cache being populated by `dns_cache_updater`. If the DNS cache does not yet contain a domain, the device cannot reach it even if the domain is in the allowlist. This is resolved the first time the device queries that domain via AdGuard.
- CIDR rules take effect immediately without DNS cache dependency.
- A device with no profile in enforcing mode falls through to the general WAN access rules at priority 50.

---

## `ml-pipeline/config/thresholds.yml`

Controls the ML pipeline's alert classification. All values can be changed on the host and take effect after restarting the ml-pipeline container.

### `thresholds` section

Isolation Forest anomaly score cutoffs. Higher score = more anomalous. Scores above `critical_threshold` produce CRITICAL alerts; above `warning_threshold` produce WARNING; above `info_threshold` produce INFO.

| Key | Default | Description |
|-----|---------|-------------|
| `info_threshold` | `0.05` | Minimum score to log an INFO alert |
| `warning_threshold` | `0.15` | Score at which alerts are promoted to WARNING |
| `critical_threshold` | `0.30` | Score at which alerts are promoted to CRITICAL |

### `rules` section

Rule-based checks that override the Isolation Forest score. These run first.

| Key | Default | Description |
|-----|---------|-------------|
| `port_scan_critical_unique_ports` | `30` | Unique destination ports in the window that trigger CRITICAL |
| `dns_rate_critical_multiplier` | `10.0` | DNS query count as multiple of baseline mean for CRITICAL |
| `dns_rate_warning_multiplier` | `2.0` | DNS query count multiple for WARNING |
| `volume_critical_multiplier` | `10.0` | Traffic volume multiple for CRITICAL |
| `volume_warning_multiplier` | `3.0` | Traffic volume multiple for WARNING |
| `failed_conn_critical_rate` | `0.80` | Proportion of failed connections (S0/REJ) for CRITICAL |
| `failed_conn_warning_rate` | `0.50` | Proportion of failed connections for WARNING |
| `dns_entropy_warning` | `3.50` | Mean DNS query name entropy (bits/char) for WARNING |
| `dns_entropy_critical` | `3.80` | Mean DNS query name entropy for CRITICAL |

### `scoring` section

| Key | Default | Description |
|-----|---------|-------------|
| `score_interval` | `60` | Seconds between scoring cycles |
| `window_seconds` | `300` | Rolling window size in seconds (5 minutes) |
| `min_baseline_observations` | `50` | Scoring cycles required before baseline-relative checks apply |
| `min_conn_entries` | `3` | Minimum `conn.log` entries in window before a device is scored |
| `dedup_seconds` | `120` | Suppress duplicate alerts for the same device and detector within this window |

---

## `zeek/site/local.zeek` - detection thresholds

Detection script thresholds are overridden using `redef` statements at the bottom of `local.zeek`. Restart Zeek after changes.

```zeek
# Port scan thresholds
redef IoT::port_scan_warning_threshold  = 15.0;   # unique dst pairs
redef IoT::port_scan_critical_threshold = 30.0;
redef IoT::port_scan_epoch              = 60 secs;

# DNS anomaly thresholds
redef IoT::dns_rate_warning_threshold   = 100.0;  # queries per epoch
redef IoT::dns_rate_critical_threshold  = 500.0;
redef IoT::dga_warning_threshold        = 5.0;    # high-entropy queries per epoch
redef IoT::dns_rate_epoch               = 60 secs;

# Volume anomaly thresholds
redef IoT::volume_warning_threshold     = 52428800.0;   # 50 MB per epoch
redef IoT::volume_critical_threshold    = 524288000.0;  # 500 MB per epoch
redef IoT::volume_epoch                 = 60 secs;

# Detection modes (switch from "learning" to "detecting" when ready)
redef IoT::new_dest_mode      = "detecting";
redef IoT::proto_anomaly_mode = "detecting";

# Enable automatic isolation (only after validating detections)
redef IoT::auto_isolate = T;
```

---

## Docker Compose environment variables

### `ml-pipeline` service

| Variable | Default | Description |
|----------|---------|-------------|
| `RYU_API_URL` | `http://ryu:8080` | Ryu REST API base URL |
| `POLL_INTERVAL` | `10` | Seconds between log file polls |
| `ZEEK_LOG_DIR` | `/opt/zeek-logs` | Path to Zeek log volume |
| `MODELS_DIR` | `/opt/ml-pipeline/models` | Directory containing `.joblib` model files |
| `CONFIG_PATH` | `/opt/ml-pipeline/config/thresholds.yml` | Path to thresholds config |
| `ML_ALERT_LOG` | `/opt/zeek-logs/ml_alerts.log` | Output path for ML alerts |
| `ML_AUTO_ISOLATE` | `false` | Set to `true` to enable automatic device isolation |
