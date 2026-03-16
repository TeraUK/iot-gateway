# Architecture Overview

The gateway is built on a layered defence model. Each layer operates independently so that if one is bypassed or fails, the others continue to provide protection.

## Design principles

**Default deny.** OVS drops all traffic by default. Every permitted flow requires an explicit OpenFlow rule installed by Ryu. There is no "allow all" fallback.

**Least privilege.** Once device profiles are established, each device can only reach the destinations it legitimately needs. General WAN access is a temporary Phase 2 state, replaced by per-device allowlists in Phase 3.

**Defence in depth.** No single layer is solely responsible for security:

| Layer | Mechanism | What it stops |
|-------|-----------|---------------|
| WiFi | WPA2-PSK (hostapd) | Unauthorised wireless association |
| DNS | AdGuard Home + nftables DNAT | C2 domain resolution, DNS tunnelling, telemetry |
| Network | OVS OpenFlow rules (Ryu) | Lateral movement, unapproved destinations |
| Analysis | Zeek detection scripts | Port scanning, DNS anomalies, known-bad IOCs |
| Analysis | ML pipeline | Behavioural anomalies missed by rules |
| Response | Ryu isolation API | Quarantine of compromised devices |

## Component map

```
┌──────────────────────────────────────────────────────────────┐
│  Ubuntu Server 24.04 LTS                                     │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  Native (data path)                                     │ │
│  │                                                         │ │
│  │   enp2s0 ──── WAN (DHCP from upstream router)          │ │
│  │   wlp3s0 ──── WiFi radio (WPA2-PSK, hostapd)           │ │
│  │   br0    ──── OVS bridge 192.168.50.1/24               │ │
│  │   nftables ── NAT masquerade + DNS DNAT                 │ │
│  │   dnsmasq ─── DHCP server (range .50–.150)              │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  Docker (gateway-net 172.20.0.0/24)                     │ │
│  │                                                         │ │
│  │   Ryu SDN Controller  ── OpenFlow :6653, REST :8080     │ │
│  │   AdGuard Home        ── DNS :53 (172.20.0.53 static)   │ │
│  │   Zeek                ── Passive capture (zeek-eth1)    │ │
│  │   ML Pipeline         ── Reads zeek-logs volume         │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

## Traffic path for a typical IoT device

1. Device associates with `IoT-Security-AP` via WPA2-PSK.
2. `wlp3s0` is an OVS port, so the device's traffic enters the OVS data plane immediately.
3. OVS sends the DHCP broadcast to the controller (table-miss). Ryu has a proactive rule permitting DHCP to `192.168.50.1`. dnsmasq assigns an IP.
4. A copy of all traffic on the bridge is mirrored to Zeek via a veth pair (`zeek-veth-h` → `zeek-eth1`).
5. When the device makes a DNS query, nftables intercepts it (DNAT prerouting) and redirects it to AdGuard at `172.20.0.53`, regardless of the target DNS server.
6. For outbound HTTP/HTTPS, OVS checks against the device's allowlist rules. If the destination is permitted, the packet is forwarded via `OFPP_LOCAL` (the host IP stack) and NATed to the WAN. If not permitted, the default-deny rule drops it.
7. If Zeek or the ML pipeline detect anomalous behaviour, they POST to `ryu:8080/policy/isolate`. Ryu installs a priority-65535 DROP rule for all traffic from that MAC.

## Startup dependency order

The components must start in this order to avoid timing failures:

```
ovs-vswitchd → hostapd → dnsmasq → Docker containers → zeek-mirror.service
```

`systemd` service overrides in `config/hostapd/override.conf` and `config/dnsmasq/override.conf` enforce the first three. `docker compose` handles the container order via `depends_on`. The `zeek-mirror.service` systemd unit watches Docker events and re-attaches the mirror veth pair whenever Zeek restarts.

## What is not yet implemented

| Item | Status | Notes |
|------|--------|-------|
| WPA3 support | Not yet | Hardware driver limitation identified in R02 |
| OVS secure fail mode | Phase 5 | Pending Ryu stability validation |
| ML auto-isolation | Disabled by default | Enable after baseline validation |
| Observability stack | Out of scope | Acknowledged in NFR-08 (Won't Have) |
