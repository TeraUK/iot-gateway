# detect-protocol-anomaly.zeek

**Location:** `zeek/site/iot-detection/detect-protocol-anomaly.zeek`

Tracks which destination ports each IoT device uses. In `learning` mode it
builds a per-device baseline. In `detecting` mode it flags new ports as
INFO and always generates a WARNING for connections to a hardcoded set of
ports that are inherently suspicious for IoT devices regardless of baseline
status (SSH/22, Telnet/23 and 2323, FTP/21, IRC/6667 and 6697,
Metasploit/4444, ADB/5555).

Default options (override in `local.zeek`):

| Option | Default | Notes |
|--------|---------|-------|
| `proto_anomaly_mode` | `"learning"` | Switch to `"detecting"` once baseline is established |
| `suspicious_ports` | See above | Can be extended via `redef` |

---

```text
--8<-- "zeek/site/iot-detection/detect-protocol-anomaly.zeek"
```
