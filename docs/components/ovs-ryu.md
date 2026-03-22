# OVS and Ryu

Open vSwitch (OVS) is the data plane. It forwards packets according to OpenFlow rules installed by the Ryu SDN controller. Together they implement the enforcement layer for POL-01 (micro-segmentation), POL-02 (per-device allowlists), POL-04 (default-deny), POL-05 (essential services), POL-07 (dynamic isolation), and the lateral movement permit system.

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
| `standalone` | Falls back to learning switch (all traffic flows) | Phase 1-4 |
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

# Show only lateral permit rules (priority 160)
sudo ovs-ofctl dump-flows br0 -O OpenFlow13 | grep priority=160

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
4. **DHCP** (priority 200) - permit DHCP between devices and the gateway. Both the request (port 67) and response (port 68) rules also send a copy to the controller for DHCP snooping (see below).
5. **DNS** (priority 200) - permit DNS queries to `192.168.50.1` (intercepted by nftables to AdGuard).
6. **NTP** (priority 200) - permit NTP queries and responses.
7. **Anti-lateral-movement** (priority 550) - drop any IPv4 traffic from `wlp3s0` destined for `192.168.50.0/24`. Sits above the per-device allowlist (500), so an allowlist entry for a `192.168.50.x` address can never grant lateral movement. Lateral movement can only be permitted via the lateral permit API.
8. **Upstream LAN block** (priority 75) - drop any IPv4 traffic from `wlp3s0` destined for an RFC1918 private address range (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). Sits below the per-device allowlist (500), so a device with an explicit allowlist entry for an upstream LAN server can still reach it. All other devices, including those in learning mode, cannot reach the upstream LAN by default.
9. **General WAN access** (priority 50) - allow all IPv4 traffic in and out (overridden by per-device intercept rules in Phase 3).
10. **Per-device intercept** (priority 100, enforcing mode only) - for profiled devices, send unmatched flows to the controller for allowlist evaluation before installing a forward or drop rule.
11. **Lateral permit rules** (priority 600, dynamic) - reinstalled on reconnect for any permits that existed before the controller restarted. See [Per-pair lateral permits](#per-pair-lateral-permits) below.

### Flow rule priority scheme

| Priority | Rule type | Description |
|----------|-----------|-------------|
| 65535 | Isolation | Per-device DROP rule (dynamic, installed on alert) |
| 600 | Lateral permit | Per-pair exception to the anti-lateral-movement rule (dynamic, API-controlled only) |
| 550 | Anti-lateral-movement | Drops IoT-to-IoT routed traffic via gateway. Sits above the allowlist — an allowlist entry cannot grant lateral movement |
| 500 | Allowlist | Per-device destination FORWARD rules (Phase 3, reactive). Can include upstream LAN addresses for devices that legitimately need them |
| 200 | Essential services | DHCP, DNS, NTP, ARP - universally permitted |
| 100 | Per-device intercept | Matches profiled devices in enforcing mode |
| 75 | Upstream LAN block | Drops traffic destined for RFC1918 ranges by default. Sits below the allowlist — a specific upstream LAN IP can be granted via a device allowlist entry |
| 50 | General WAN | Allows all devices to reach the internet (overridden by per-device rules) |
| 1 | Default deny | Drops everything not explicitly permitted |
| 0 | Table-miss | Sends unmatched packets to controller |

Higher priority wins. The isolation rule at 65535 overrides everything else, including lateral permits and essential services.

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
# Drop all traffic FROM the device (WiFi -> anywhere)
match: in_port=wifi, eth_src=<mac>  ->  actions: DROP

# Drop all traffic TO the device (anywhere -> WiFi)
match: in_port=LOCAL, eth_dst=<mac>  ->  actions: DROP
```

Priority 65535 overrides every other rule including essential services and lateral permits. An isolated device has no network connectivity whatsoever until the isolation is released.

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

### Per-pair lateral permits

By default all IoT-to-IoT traffic is dropped by the anti-lateral-movement rule at priority 150. An administrator can grant bidirectional unicast communication between a specific pair of devices using the lateral permit API. Permits are dynamic - they take effect immediately and can be revoked at any time without restarting any component.

When a permit is created, Ryu installs four OpenFlow rules at priority 160:

```
# Outbound A -> B
match: in_port=wifi, eth_src=MAC_A, ipv4_dst=IP_B  ->  OFPP_LOCAL

# Outbound B -> A
match: in_port=wifi, eth_src=MAC_B, ipv4_dst=IP_A  ->  OFPP_LOCAL

# Return traffic to A
match: in_port=LOCAL, eth_dst=MAC_A, ipv4_src=IP_B  ->  wifi

# Return traffic to B
match: in_port=LOCAL, eth_dst=MAC_B, ipv4_src=IP_A  ->  wifi
```

These rules override the anti-lateral-movement drop at priority 150 for the specific permitted pair, while all other device-to-device traffic continues to be blocked.

**Pre-requisites for lateral permits:**

Proxy ARP must be enabled on `br0` so devices can resolve each other's IP address via ARP. Because `ap_isolate=1` in hostapd prevents direct ARP between associated stations, the gateway kernel must respond on each device's behalf. Both of the following sysctl settings are required:

```bash
sudo sysctl -w net.ipv4.conf.br0.proxy_arp=1
sudo sysctl -w net.ipv4.conf.br0.proxy_arp_pvlan=1
```

`proxy_arp_pvlan` is specifically required because both devices are reachable via the same interface (`br0`). Standard `proxy_arp` alone refuses to answer in this case.

Make persistent in `/etc/sysctl.d/99-iot-gateway.conf`:

```
net.ipv4.conf.br0.proxy_arp = 1
net.ipv4.conf.br0.proxy_arp_pvlan = 1
```

**IP change handling:** If a device receives a new DHCP lease and its IP changes, Ryu automatically tears down the stale permit rules and reinstalls them using the new IP. This is triggered by observing the new source IP in the first PacketIn event from the device after the IP change.

**Permit persistence across controller restarts:** Lateral permit metadata is stored in Ryu's in-memory state. If Ryu restarts, the permit entries are lost. Permits must be re-created after a Ryu restart. The OpenFlow rules are reinstalled automatically when the switch reconnects if the permit record still exists in memory.

**Known limitation - multicast service discovery:** Devices cannot discover each other by hostname or service name (mDNS, SSDP) because those protocols rely on multicast which is also blocked by `ap_isolate`. The administrator must know the IP addresses of both devices before creating a permit. See [hostapd](hostapd.md) for a full discussion of this limitation.

```bash
# Create a permit between two devices
curl -X POST http://127.0.0.1:8080/policy/lateral-permits \
     -H 'Content-Type: application/json' \
     -d '{"mac_a": "aa:bb:cc:dd:ee:ff", "mac_b": "11:22:33:44:55:66"}'

# List all active permits
curl -s http://127.0.0.1:8080/policy/lateral-permits | python3 -m json.tool

# Revoke a permit
curl -X DELETE http://127.0.0.1:8080/policy/lateral-permits \
     -H 'Content-Type: application/json' \
     -d '{"mac_a": "aa:bb:cc:dd:ee:ff", "mac_b": "11:22:33:44:55:66"}'
```

For the full API reference see [REST API](../reference/api.md).

### Device tracking and DHCP snooping

Ryu maintains a `known_devices` table of every MAC address seen on the WiFi port, including the device's current IP address. This table is used by the lateral permit feature to resolve IP addresses at rule installation time, and is exposed via `GET /policy/devices`.

Device tracking is populated from three sources, in order of precedence:

1. **dnsmasq lease file** - read at startup from `/var/lib/misc/dnsmasq.leases`. This pre-populates the table with all devices that already hold a valid lease, so devices are immediately visible without needing to generate new traffic. Requires the lease file to be bind-mounted into the container (see `docker-compose.yml`).

2. **DHCP snooping** - the DHCP request (port 67) and response (port 68) rules in OVS each send a copy to the controller alongside their normal forwarding action. When a DISCOVER or REQUEST arrives, the device MAC is registered immediately. When an ACK arrives from dnsmasq, the assigned IP (`yiaddr`) is recorded. This handles devices that perform a full DHCP exchange after Ryu starts.

3. **IPv4 packet observation** - the source IP is extracted from every IPv4 PacketIn event. This keeps the stored IP current for devices in enforcing mode whose traffic reaches the controller via the per-device intercept rules.

If a device reconnects using a cached lease and does not perform a new DHCP exchange, it will appear in the table immediately via source 1 (lease file pre-population) after each Ryu restart.

## DNS cache update loop

Domain-based allowlists in Ryu need to know the current IP addresses for permitted domains. The `dns_cache_updater` service watches Zeek's `dns.log` and pushes domain-to-IP mappings to Ryu via `POST /policy/dns-cache`. Ryu stores these mappings in memory and consults them when evaluating allowlist rules for profiled devices.

```bash
# View current DNS cache
curl -s http://127.0.0.1:8080/policy/dns-cache | python3 -m json.tool
```

## docker-compose.yml volume mounts

The Ryu container requires two mounts:

```yaml
volumes:
  - ./ryu/config:/opt/ryu/config:ro
  - /var/lib/misc/dnsmasq.leases:/var/lib/misc/dnsmasq.leases:ro
```

The first provides the device profiles configuration. The second provides the dnsmasq lease file for startup pre-population of `known_devices`. Without the lease file mount, devices with cached leases will not appear in `/policy/devices` until they next perform a full DHCP exchange.
