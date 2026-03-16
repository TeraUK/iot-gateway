# Alert Response

This page covers what to do when an alert fires - how to investigate, decide whether the isolation is justified, and either clear the device or confirm the incident.

## Alert sources

Alerts come from two sources, both writing to the shared log volume:

| Source | Log file | Detector names |
|--------|----------|----------------|
| Zeek detection scripts | `/opt/zeek-logs/iot_alerts.log` | `port-scan`, `dns-rate`, `dns-dga`, `new-destination`, `protocol-anomaly`, `volume-anomaly`, `known-bad-ip`, `known-bad-domain` |
| ML pipeline | `/opt/zeek-logs/ml_alerts.log` | `ml-isolation-forest` |

## Reading the alert logs

```bash
# Tail both alert logs in real time
tail -f /var/lib/docker/volumes/iot-gateway_zeek-logs/_data/iot_alerts.log \
         /var/lib/docker/volumes/iot-gateway_zeek-logs/_data/ml_alerts.log \
  | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line or line.startswith('==>'):
        print(line); continue
    try:
        e = json.loads(line)
        print(f'[{e[\"severity\"]}] {e[\"ts\"]} | {e[\"src_mac\"]} | {e[\"detector\"]} | {e[\"description\"][:100]}')
    except:
        pass
"
```

```bash
# Show all CRITICAL alerts from today
grep '"severity": "CRITICAL"' /var/lib/docker/volumes/iot-gateway_zeek-logs/_data/iot_alerts.log \
  | python3 -c "import sys,json; [print(json.loads(l)['src_mac'], json.loads(l)['description']) for l in sys.stdin]"
```

## Checking which devices are currently isolated

```bash
curl -s http://127.0.0.1:8080/policy/status \
  | python3 -c "import sys,json; s=json.load(sys.stdin); print('Isolated:', s['isolated_devices'])"

curl -s http://127.0.0.1:8080/policy/devices \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
for mac, info in d['devices'].items():
    if info['is_isolated']:
        print(mac, info.get('profile_name', 'no profile'), 'ISOLATED since', info.get('isolated_since', 'unknown'))
"
```

## Investigating an alert

### Step 1 - Identify the device

Get the MAC address from the alert. Cross-reference against `dnsmasq.leases` to confirm the device identity:

```bash
grep "<mac>" /var/lib/misc/dnsmasq.leases
# Output: <expiry> <mac> <ip> <hostname> <client-id>
```

### Step 2 - Understand what triggered the alert

The `details` field in every alert entry contains JSON-encoded metadata about the specific detection. Parse it to understand the specific values that crossed the threshold.

```bash
# Show full details for a specific MAC
grep '"src_mac": "aa:bb:cc:dd:ee:ff"' \
  /var/lib/docker/volumes/iot-gateway_zeek-logs/_data/iot_alerts.log \
  | tail -20 \
  | python3 -c "
import sys, json
for line in sys.stdin:
    e = json.loads(line)
    details = json.loads(e.get('details', '{}'))
    print(e['ts'], e['severity'], e['detector'])
    print('  ', e['description'])
    print('  ', details)
"
```

### Step 3 - Inspect the raw Zeek logs for the device

```bash
# Recent connections from the device
docker exec zeek grep "<ip-address>" /opt/zeek-logs/conn.log | tail -50 | python3 -m json.tool

# Recent DNS queries from the device
docker exec zeek grep "<ip-address>" /opt/zeek-logs/dns.log | tail -50 | python3 -m json.tool
```

### Step 4 - Cross-check against IOC feeds

If the alert was `known-bad-ip` or `known-bad-domain`, check the IOC file for the description:

```bash
grep "<bad-ip>" zeek/site/iot-iocs/known-bad-ips.dat
grep "<bad-domain>" zeek/site/iot-iocs/known-bad-domains.dat
```

## Decision: release or confirm isolation

### Indicators of a false positive

- The alert fired immediately after a firmware update and the device was contacting update servers.
- The destination is a known legitimate service that isn't in the allowlist yet (check against the device manufacturer's documentation).
- The `model_type` in an ML alert is `fleet` - the fleet model is less accurate than a per-device model and more likely to produce false positives for devices with unusual-but-legitimate traffic patterns.
- The detected anomaly matches a known benign event (e.g., a bulk backup that runs nightly).

### Indicators of a genuine incident

- The device contacted an IP on a threat intelligence feed.
- The device initiated connections to Telnet (23), SSH (22), or other ports it has no legitimate reason to use.
- DNS query names have high entropy with no known legitimate explanation.
- The device's traffic volume spiked massively with no corresponding user activity.
- Multiple detection types fired within a short window (correlated alerts are more reliable than a single trigger).

## Releasing an isolated device

If the isolation was a false positive:

```bash
curl -X POST http://127.0.0.1:8080/policy/release \
     -H 'Content-Type: application/json' \
     -d '{"mac": "aa:bb:cc:dd:ee:ff"}'
```

After releasing, if the trigger was a new legitimate destination, add it to the device's allowlist profile:

```bash
# Edit ryu/config/device_profiles.json, then reload
curl -X POST http://127.0.0.1:8080/policy/allowlists/reload
```

If the trigger was an ML anomaly score and not a rule-based check, review whether the `warning_threshold` or `critical_threshold` in `thresholds.yml` should be raised for this device's usage pattern, or whether the model needs retraining with more representative data.

## Updating IOC feeds

If a new C2 IP or malicious domain is identified during an investigation, add it to the IOC files. Zeek re-reads these files automatically (no restart required):

```bash
# Add a new known-bad IP
echo "203.0.113.99	New C2 server identified 2026-03-15" \
  >> zeek/site/iot-iocs/known-bad-ips.dat

# Add a new known-bad domain
echo "malicious-cdn.example.com	Malware distribution domain" \
  >> zeek/site/iot-iocs/known-bad-domains.dat
```

## Adjusting detection thresholds after false positives

If a specific detection type is producing too many false positives, raise its threshold in `zeek/site/local.zeek` and restart Zeek, or adjust `ml-pipeline/config/thresholds.yml` and restart the ML pipeline container.

Document any threshold changes and the reason for them so that the detection configuration reflects a deliberate decision rather than accumulated ad-hoc tweaks.
