## profile_builder.py

**Purpose:** Analyses Zeek `conn.log` and `dns.log` files collected during the baseline period and produces a draft `device_profiles.json` for use with Ryu's per-device allowlist enforcement. This is the entry point for Phase 3 onboarding. See [Device Onboarding](../operations/device-onboarding.md) for the full workflow.

```bash
python3 scripts/profile_builder.py --zeek-dir <path> [options]
```

**Arguments:**

| Argument | Required | Description |
|----------|----------|-------------|
| `--zeek-dir` | Yes | Path to the directory containing Zeek log files. When running against the live gateway volume this is typically `/var/lib/docker/volumes/iot-gateway_zeek-logs/_data`. The script reads logs from inside the Zeek container via `docker exec` and accepts any path that is valid inside the container (e.g. `/opt/zeek-logs`). |
| `--output` | No | Write the draft profiles to this JSON file. If omitted the script prints the summary to stdout and does not write a file. |
| `--leases` | No | Path to the dnsmasq lease file (`/var/lib/misc/dnsmasq.leases`). Without this flag, devices are identified by IP address rather than MAC address, which means a device that receives a new DHCP lease will appear as a different device in the output. Always provide this in practice. |
| `--mac` | No | Restrict the analysis to a single device, identified by MAC address (e.g. `aa:bb:cc:dd:ee:ff`). Useful when onboarding one device at a time or investigating a specific device. |
| `--min-connections` | No | Minimum number of times a destination IP must have been contacted to be included in `allowed_cidrs`. Defaults to `1`. Setting this to `2` or `3` filters out one-off CDN requests and transient update checks that should not be in the allowlist. |

**Typical invocation**

```bash
python3 scripts/profile_builder.py \
    --zeek-dir /opt/zeek-logs \
    --leases /var/lib/misc/dnsmasq.leases \
    --output /tmp/draft_profiles.json \
    --min-connections 2
```

**What the output contains:**

The script produces two lists per device. `allowed_domains` contains every domain name the device queried via DNS, sorted by query frequency. `allowed_cidrs` contains IP addresses the device connected to directly without a corresponding DNS resolution - these are added as `/32` entries and typically represent hardcoded NTP servers, update infrastructure, or manufacturer cloud endpoints that bypass DNS.

The `_stats` block in the output (total connections, unique destinations, top destinations by connection count) is for my review and is ignored by Ryu.

**Reviewing the draft output:**

Before loading the profiles into Ryu I need to review the draft and:

- Remove ad and analytics domains that AdGuard may not yet have blocked
- Remove destinations that look like one-off initialisation calls (set `--min-connections` higher to filter these automatically)
- Set a meaningful `name` and `manufacturer` for each device
- Remove the `_stats` and `_note` fields (optional; Ryu ignores them)

Once the file looks correct, copy it to `ryu/config/device_profiles.json` and reload:

```bash
curl -X POST http://127.0.0.1:8080/policy/allowlists/reload
```
