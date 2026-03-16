# OVS and Ryu

Open vSwitch (OVS) is the data plane. It forwards packets according to OpenFlow rules installed by the Ryu SDN controller. Together they implement the enforcement layer for POL-01 (micro-segmentation), POL-02 (per-device allowlists), POL-04 (default-deny), POL-05 (essential services), and POL-07 (dynamic isolation).

## Open vSwitch

OVS runs natively on the host. It manages the `br0` bridge, which has two ports: `wlp3s0` (the WiFi radio, where IoT device traffic enters) and `OFPP_LOCAL` (the internal port, which connects OVS to the host IP stack and from there to the WAN via nftables NAT).

### Initial setup

```bash
sudo /usr/local/bin/setup-native-ovs.sh
```

This script creates the bridge, adds `wlp3s0` as a port, assigns `192.168.50.1/24` to the bridge's internal port, sets the fail mode to `standalone` (development), and points the controller at `tcp:127.0.0.1:6653`.

### Fail mode

| Mode | Behaviour when Ryu is unreachable | Current setting |
|------|----------------------------------|-----------------|
| `standalone` | Falls back to learning switch (all traffic flows) | Phase 1–4 |
| `secure` | Drops all traffic | Phase 5 (production) |

Switch to secure mode only after Ryu has been running reliably for an extended period:

```bash
sudo ovs-vsctl set-fail-mode br0 secure
```

### Useful commands

```bash
# Show bridge and port configuration
ovs-vsctl show

# Show all flow rules installed by Ryu
sudo ovs-ofctl dump-flows br0 -O OpenFlow13

# Show only isolation rules (priority 65535)
sudo ovs-ofctl dump-flows br0 -O OpenFlow13 | grep priority=65535

# Check the controller connection
ovs-vsctl get-controller br0
```

## Ryu SDN controller

Ryu runs as a Docker container. The `gateway_policy.py` application is the only Ryu app loaded. It handles OpenFlow events and exposes a REST API for policy management.

### Policy application: `gateway_policy.py`

On switch connection, the app installs proactive flow rules in this order:

1. **Table-miss** (priority 0) - unmatched packets go to the controller.
2. **Default deny** (priority 1) - drop everything not explicitly allowed.
3. **ARP** (priority 200) - permit ARP between devices and the gateway.
4. **DHCP** (priority 200) - permit DHCP broadcasts to `192.168.50.1`.
5. **DNS** (priority 200) - permit DNS queries to `192.168.50.1` (intercepted by nftables to AdGuard).
6. **NTP** (priority 200) - permit NTP queries and responses.
7. **Anti-lateral-movement** (priority 150) - drop any IPv4 traffic from `wlp3s0` destined for `192.168.50.0/24`. This prevents IoT devices from reaching each other even if they try to bypass the gateway.
8. **General WAN access** (priority 50) - allow all IPv4 traffic in and out (overridden by per-device intercept rules in Phase 3).
9. **Per-device intercept** (priority 100, enforcing mode only) - for profiled devices, send unmatched flows to the controller to check against the allowlist before installing a forward or drop rule.

### Enforcement modes

| Mode | Behaviour |
|------|-----------|
| `learning` | All devices get general WAN access. Connection destinations are observed and logged. |
| `enforcing` | Profiled devices are intercepted at priority 100. Traffic to non-allowlisted destinations is dropped. Unprofiled devices still get general WAN access. |

Switch mode via the API:

```bash
curl -X POST http://127.0.0.1:8080/policy/allowlists/mode \
     -H 'Content-Type: application/json' \
     -d '{"mode": "enforcing"}'
```

### Device isolation

Isolation installs two rules at priority 65535:

```
# Drop all traffic FROM the device (WiFi → anywhere)
match: in_port=wifi, eth_src=<mac>  →  actions: DROP

# Drop all traffic TO the device (anywhere → WiFi)  
match: in_port=LOCAL, eth_dst=<mac>  →  actions: DROP
```

Priority 65535 overrides every other rule including essential services. An isolated device has no network connectivity whatsoever until the isolation is released.

```bash
# Manually isolate a device
curl -X POST http://127.0.0.1:8080/policy/isolate \
     -H 'Content-Type: application/json' \
     -d '{"mac": "aa:bb:cc:dd:ee:ff", "reason": "manual"}'

# Release isolation
curl -X POST http://127.0.0.1:8080/policy/release \
     -H 'Content-Type: application/json' \
     -d '{"mac": "aa:bb:cc:dd:ee:ff"}'
```

For the full API reference, see [REST API](../reference/api.md).

### Device profiles (`device_profiles.json`)

Each device profile maps a MAC address to a set of permitted destinations:

```json
{
  "aa:bb:cc:dd:ee:ff": {
    "name": "Smart Thermostat",
    "allowed_domains": ["api.vendor.com", "cloud.vendor.com"],
    "allowed_cidrs": ["203.0.113.0/24"]
  }
}
```

Domain-based rules rely on the DNS cache (populated by `dns_cache_updater`). CIDR rules match directly in OVS without requiring DNS resolution. See [Device Onboarding](../operations/device-onboarding.md) for how to create profiles.

Profiles are stored at `ryu/config/device_profiles.json` and mounted read-only into the container. Apply changes without restarting:

```bash
curl -X POST http://127.0.0.1:8080/policy/allowlists/reload
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

see [DNS Cache Updater](../services/dns-cache-updater.md)

---