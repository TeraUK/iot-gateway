# Data Flow

This page traces how data moves between components — from raw network traffic through to an isolation action — and provides a complete inventory of every log the system produces, where it is stored, who writes it, and how long it is kept.

---

## Log production pipeline

```
OVS (br0)
    │  mirror copy of all bridge traffic
    ▼
Zeek (zeek-eth1)
    │  writes JSON log lines (one file per protocol)
    ▼
zeek-logs Docker volume (/opt/zeek-logs/)
    │  conn.log  dns.log  http.log  ssl.log  dhcp.log
    │  ntp.log   ssh.log  ftp.log   software.log
    │  iot_alerts.log
    ▼
ML Pipeline (reads via volume mount)
    │  writes ml_alerts.log
    ▼
zeek-logs Docker volume

IoT devices (DNS queries, all destinations)
    │  nftables DNAT intercepts all port-53 traffic
    ▼
AdGuard Home (172.20.0.53)
    │  writes query log
    ▼
adguard/work/data/ (bind mount on host)
    │  querylog.json  statistics.db

IoT devices (DHCP, WiFi association)
    │
    ├── dnsmasq: lease events → /var/log/syslog
    │            active leases → /var/lib/misc/dnsmasq.leases
    └── hostapd: association/auth events → /var/log/syslog

nftables (DoT/DoQ block events)
    │
    └── → kernel log → /var/log/kern.log (prefix IOT-DOT-BLOCKED / IOT-DOQ-BLOCKED)
```

---

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

see [Zeek](../components/zeek.md)

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

see [ML-Pipeline](../components/ml-pipeline.md)

---

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

see [DNS Cache Updater](../services/dns-cache-updater.md)

---

## Complete log inventory

### Zeek logs — `zeek-logs` Docker volume

All files live inside the container at `/opt/zeek-logs/` and on the host at the Docker volume mount path (`/var/lib/docker/volumes/iot-gateway_zeek-logs/_data`). All files are JSON, one object per line. Zeek rotates each file hourly, producing timestamped archive files that `log-maintenance.sh` compresses and moves to `/opt/zeek-logs/archive/`.

| File | Written by | Content | Used by |
|------|-----------|---------|---------|
| `conn.log` | Zeek | TCP/UDP/ICMP connection summaries — src/dst IP, port, proto, bytes, duration, conn state | ML pipeline (primary feature source), profile_builder.py |
| `dns.log` | Zeek | DNS queries and responses — query name, type, rcode, answer IPs | ML pipeline, dns_cache_updater, profile_builder.py |
| `http.log` | Zeek | HTTP transactions — method, URI, host, status, User-Agent, response bytes | ML pipeline, manual investigation |
| `ssl.log` | Zeek | TLS connections — SNI hostname, cert subject/issuer, validation status, cipher | ML pipeline, manual investigation |
| `dhcp.log` | Zeek | DHCP lease assignments — MAC, assigned IP, hostname, lease time | ML pipeline (IP→MAC resolution), profile_builder.py |
| `ntp.log` | Zeek | NTP traffic — server IP, stratum, reference ID | Anomaly investigation |
| `ssh.log` | Zeek | SSH connections — client/server version, auth outcome | Detection scripts (IoT devices should never initiate SSH) |
| `ftp.log` | Zeek | FTP connections — command, reply, data transfer size | Detection scripts (IoT devices should never initiate FTP) |
| `software.log` | Zeek | Software fingerprints — HTTP User-Agents, SSH banners, DHCP vendor class | Baseline deviation detection |
| `iot_alerts.log` | Zeek alert framework | Rule-based detection alerts — severity, detector, src MAC/IP, description, action taken | Alert response workflow, manual investigation |
| `ml_alerts.log` | ML pipeline alerter | Isolation Forest anomaly alerts — same schema as `iot_alerts.log` plus anomaly score and model type | Alert response workflow, manual investigation |

**Archive location:** `/opt/zeek-logs/archive/` — compressed `.log.gz` files, retained for 90 days.

**Accessing logs:**

```bash
# Read active logs from inside the Zeek container
docker exec zeek cat /opt/zeek-logs/conn.log | python3 -m json.tool | head -20

# Read compressed archive files
docker exec zeek zcat /opt/zeek-logs/archive/conn.2026-03-15-11-00-00.log.gz | head

# Read from the host volume mount directly
sudo cat /var/lib/docker/volumes/iot-gateway_zeek-logs/_data/conn.log
```

see [Zeek](../components/zeek.md)

---

### AdGuard Home logs — `adguard/work/` bind mount

AdGuard's data directory is bind-mounted from the repository into the container (`./adguard/work:/opt/adguardhome/work`), so all files are accessible directly on the host under `adguard/work/`.

| File | Content | Retention |
|------|---------|-----------|
| `adguard/work/data/querylog.json` | Every DNS query processed by AdGuard — timestamp, client IP, query domain, query type, response, whether it was blocked and by which rule, upstream resolver used, response time | 90 days (2160h), configured in `adguard/conf/AdGuardHome.yaml` |
| `adguard/work/data/stats.db` | Aggregated statistics — query counts, blocked counts, top blocked domains, top querying clients, top upstream servers | 30 days (720h), configured in `adguard/conf/AdGuardHome.yaml` |

AdGuard manages its own retention internally. The `log-maintenance.sh` script verifies the data directory exists but does not touch these files.

**What the query log captures that Zeek does not:** AdGuard logs whether a domain was blocked and which blocklist rule matched. Zeek's `dns.log` records the NXDOMAIN response but does not identify the blocking reason. The AdGuard query log is therefore the authoritative source for understanding which IoT device tried to reach which blocked domain and why it was blocked.

**Accessing the query log:**

```bash
# View recent queries via the AdGuard admin UI
# http://<gateway-host>:8088  → Query Log tab

# Or read the raw file
cat adguard/work/data/querylog.json | python3 -m json.tool | head -40

# Filter for blocked queries only
grep '"Result":{"IsFiltered":true' adguard/work/data/querylog.json | head
```

see [AdGuard Home](../components/adguard.md)

---

### Ryu denied-log — in-memory, REST API

When a profiled device attempts to reach a destination not in its allowlist, Ryu logs the attempt to an in-memory circular buffer (capped at the last 1000 entries). This log is not written to disk and is lost on Ryu restart.

| Access method | URL |
|--------------|-----|
| REST API | `GET http://127.0.0.1:8080/policy/denied-log` |

Each entry contains:

| Field | Description |
|-------|-------------|
| `timestamp` | ISO-8601 timestamp of the denied connection |
| `mac` | Device MAC address |
| `dst_ip` | Destination IP that was denied |
| `reason` | Why it was denied (e.g. `not in allowlist for Living Room Thermostat`) |
| `device_name` | Human-readable name from the device profile |

**Note:** Because this log is in-memory only, denied connections that occur while Ryu is restarting are not recorded. For persistent denied-connection history, cross-reference Zeek's `conn.log` for connections in `S0` or `REJ` state from IoT device IPs to non-allowlisted destinations.

```bash
# View denied connections
curl -s http://127.0.0.1:8080/policy/denied-log | python3 -m json.tool

# Filter for a specific device
curl -s http://127.0.0.1:8080/policy/denied-log | \
  python3 -c "import sys,json; d=json.load(sys.stdin); \
  [print(e['timestamp'], e['dst_ip'], e['reason']) \
   for e in d['entries'] if e['mac']=='aa:bb:cc:dd:ee:ff']"
```

see [ovs-ryu](../components/ovs-ryu.md)

---

### dnsmasq logs — host filesystem

| Location | Content | Notes |
|----------|---------|-------|
| `/var/lib/misc/dnsmasq.leases` | Active DHCP leases — expiry time, MAC, IP, hostname, client ID | Updated live as leases are assigned or renewed. This file is the primary source for IP-to-MAC mapping used by `profile_builder.py` and the ML pipeline |
| `/var/log/syslog` | DHCP assignment, renewal, and expiry events | Written by dnsmasq via syslog. Search with `grep dnsmasq /var/log/syslog` |

The lease file is small and does not require rotation. It is verified by `log-maintenance.sh` but not modified by it.

```bash
# View active leases
cat /var/lib/misc/dnsmasq.leases

# Follow DHCP events in real time
sudo journalctl -fu dnsmasq
```

see [dnsmasq](../components/dnsmasq.md)

---

### hostapd logs — host syslog

hostapd writes all WiFi association, authentication, and deauthentication events to syslog.

| Location | Content |
|----------|---------|
| `/var/log/syslog` | WPA2 association attempts (success and failure), deauthentication events, client connects and disconnects |

```bash
# View recent hostapd events
grep hostapd /var/log/syslog | tail -50

# Follow WiFi association events live
sudo journalctl -fu hostapd
```

These logs are the first place to check when a device cannot connect to `IoT-Security-AP` or is repeatedly disconnecting.

see [hostapd](../components/hostapd.md)

---

### nftables kernel log — blocked DoT/DoQ events

The nftables ruleset logs DNS-over-TLS (port 853) and DNS-over-QUIC (port 8853) block events to the kernel log with prefixed messages.

| Location | Prefix | Trigger |
|----------|--------|---------|
| `/var/log/kern.log` or `/var/log/syslog` | `IOT-DOT-BLOCKED:` | Device attempted DNS-over-TLS (port 853) |
| `/var/log/kern.log` or `/var/log/syslog` | `IOT-DOQ-BLOCKED:` | Device attempted DNS-over-QUIC (port 8853) |

Each log entry includes the source IP, destination IP, and interface. A device that frequently generates these events is attempting to bypass AdGuard using encrypted DNS — this is a meaningful signal that the device may have a hardcoded encrypted resolver.

```bash
# View DoT/DoQ block events
sudo grep -E "IOT-DO[TQ]-BLOCKED" /var/log/syslog | tail -20

# Count events per source IP
sudo grep "IOT-DOT-BLOCKED" /var/log/syslog | \
  grep -oP 'SRC=\S+' | sort | uniq -c | sort -rn
```

see [nftables](../components/nftables.md)

---

### Log maintenance output

| Location | Content |
|----------|---------|
| `/var/log/gateway-maintenance.log` | Output from the daily `log-maintenance.sh` cron run — compression counts, retention pruning counts, volume disk usage, AdGuard and dnsmasq health checks |

```bash
# View recent maintenance runs
tail -50 /var/log/gateway-maintenance.log
```

---

## Diagnostic and error logs

These logs are for diagnosing problems with the gateway itself rather than recording IoT device activity.

### Container logs

All Docker containers write their application logs to stdout/stderr, which Docker captures via its logging driver. These are the first place to check when a container is not behaving as expected.

| Container | What it logs |
|-----------|-------------|
| `ryu-controller` | OpenFlow connection events, rule installation, policy app startup, REST API errors, ALLOW/DENY decisions, isolation requests |
| `zeek` | Startup output from `entrypoint.sh` (waiting for mirror interface), Zeek engine startup, detection script load errors, processing errors |
| `adguard-home` | Startup messages, upstream resolver errors, blocklist sync results |
| `ml-pipeline` | Pipeline startup, model load results, per-scoring-cycle summaries, Ryu API errors, alert dispatches |

```bash
# View container logs (last 100 lines)
docker logs --tail 100 ryu-controller
docker logs --tail 100 zeek
docker logs --tail 100 adguard-home
docker logs --tail 100 ml-pipeline

# Follow a container's logs live
docker logs -f ryu-controller

# Show logs since a specific time
docker logs --since "1h" ml-pipeline
```

### systemd service logs

The two host services write to the systemd journal.

| Service | What it logs |
|---------|-------------|
| `zeek-mirror.service` | veth pair creation steps, OVS port and mirror configuration, container start event detection, cleanup on stop |
| `dns-cache-updater.service` | Ryu API connection status, domains being tracked, DNS mappings pushed, poll cycle errors |

```bash
# View service logs
sudo journalctl -u zeek-mirror -n 100
sudo journalctl -u dns-cache-updater -n 100

# Follow live
sudo journalctl -u zeek-mirror -f
sudo journalctl -u dns-cache-updater -f
```

### OVS logs

OVS writes operational logs to its own log directory on the host.

| File | Content |
|------|---------|
| `/var/log/openvswitch/ovs-vswitchd.log` | Bridge events, port additions, controller connections, flow mod operations, error conditions |
| `/var/log/openvswitch/ovsdb-server.log` | Database operations |

```bash
# View OVS daemon log
sudo tail -100 /var/log/openvswitch/ovs-vswitchd.log

# Check controller connection state
sudo ovs-vsctl show | grep -A2 Controller
```

---

## Timing and retention summary

| Event | Interval | Configured by |
|-------|----------|---------------|
| Log file poll (ML pipeline) | 10 seconds | `POLL_INTERVAL` env var in `docker-compose.yml` |
| ML scoring cycle | 60 seconds | `score_interval` in `thresholds.yml` |
| DNS cache update poll | 10 seconds | `POLL_INTERVAL` env var in `dns-cache-updater.service` |
| DNS full cache refresh | 300 seconds | `FULL_REFRESH_INTERVAL` env var in `dns-cache-updater.service` |
| Zeek log rotation | 1 hour | `Log::default_rotation_interval` in `local.zeek` |
| Log compression | Daily (cron 03:00) | `log-maintenance.sh` |
| Zeek log retention | 90 days | `log-maintenance.sh` |
| AdGuard query log retention | 90 days (2160h) | `adguard/conf/AdGuardHome.yaml` |
| AdGuard statistics retention | 30 days (720h) | `adguard/conf/AdGuardHome.yaml` |
| Ryu denied-log retention | In-memory, last 1000 entries | `gateway_policy.py` (`denied_log_max`) |
