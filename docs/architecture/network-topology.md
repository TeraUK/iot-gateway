# Network Topology

## Address summary

### Host interfaces

| Interface | Address | Role |
|-----------|---------|------|
| `enp2s0` | DHCP from upstream router (e.g., `192.168.2.x`) | WAN uplink |
| `wlp3s0` | None (bridged into OVS) | WiFi radio |
| `br0` (OVS internal) | `192.168.50.1/24` | IoT subnet gateway, dnsmasq binds here |

### Docker network (`gateway-net`)

| Container | Address | Role |
|-----------|---------|------|
| Docker bridge | `172.20.0.1` | Gateway for `gateway-net` |
| AdGuard Home | `172.20.0.53` (static) | DNS resolver for IoT clients |
| Ryu Controller | `172.20.0.x` (DHCP) | SDN control plane |
| Zeek | `172.20.0.x` (DHCP) | Passive analysis |
| ML Pipeline | `172.20.0.x` (DHCP) | Anomaly detection |

### IoT subnet

| Entity | Address | Assignment |
|--------|---------|------------|
| IoT devices | `192.168.50.50` – `192.168.50.150` | dnsmasq DHCP |
| Gateway | `192.168.50.1` | Static (OVS internal port) |
| Advertised DNS | `192.168.50.1` | DHCP option 6 (redirected to AdGuard by nftables) |

## Port mappings

| Host binding | Container port | Service |
|--------------|----------------|---------|
| `0.0.0.0:6653` | `6653/tcp` | Ryu OpenFlow listener |
| `0.0.0.0:8080` | `8080/tcp` | Ryu REST API |
| `192.168.50.1:53` | `53/tcp+udp` | AdGuard DNS (IoT-facing) |
| `0.0.0.0:3000` | `3000/tcp` | AdGuard initial setup wizard |
| `0.0.0.0:8088` | `80/tcp` | AdGuard admin UI |

The Ryu REST API (`8080`) is mapped to all interfaces. On a production deployment this should be restricted to the loopback or a management interface. Currently the nftables policy does not forward packets from the IoT subnet to the Docker bridge, so IoT devices cannot reach the API directly - but this is a configuration dependency rather than a hard rule.

## Mirror infrastructure

Zeek receives a copy of all OVS bridge traffic via a veth pair:

| Interface | Location | Role |
|-----------|----------|------|
| `zeek-veth-h` | Host (OVS port) | Host-side end of mirror pair |
| `zeek-eth1` | Zeek container | Container-side end; Zeek sniffs on this |

The `zeek-mirror.service` systemd unit manages the lifetime of this veth pair. It watches for Docker `start` events for the `zeek` container and re-creates the pair and OVS mirror configuration each time Zeek restarts.

## DNS interception

nftables intercepts all DNS traffic from the IoT subnet before it leaves the host:

```
# Prerouting chain (DNAT)
# Matches: any UDP/TCP port 53 from 192.168.50.0/24
# Redirects: to AdGuard at 172.20.0.53

table inet filter {
    chain input {
        type filter hook input priority 0; policy accept;
    }
    chain forward {
        type filter hook forward priority 0; policy accept;
        iifname "br0" ip saddr 192.168.50.0/24 tcp dport 853 counter log prefix "IOT-DOT-BLOCKED: " drop
        iifname "br0" ip saddr 192.168.50.0/24 udp dport 8853 counter log prefix "IOT-DOQ-BLOCKED: " drop
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
```

This defeats devices with hardcoded DNS resolvers (e.g., Google Smart Home devices that use `8.8.8.8` regardless of DHCP settings). The device's DNS query is answered by AdGuard regardless of what destination the device intended.

DNS-over-TLS (port 853) and DNS-over-QUIC (port 8853) are blocked at the nftables layer so that devices cannot bypass AdGuard using encrypted DNS protocols.

## OVS flow rule priority scheme

| Priority | Rule type | Description |
|----------|-----------|-------------|
| 65535 | Isolation | Per-device DROP rule (dynamic, installed on alert) |
| 500 | Allowlist | Per-device destination FORWARD rules (Phase 3) |
| 200 | Essential services | DHCP, DNS, NTP, ARP - universally permitted |
| 150 | Anti-lateral-movement | Drops IoT→IoT traffic via gateway routing |
| 100 | Per-device intercept | Matches profiled devices in enforcing mode |
| 50 | General WAN | Allows all devices to reach the internet (Phase 2, overridden by per-device rules) |
| 1 | Default deny | Drops everything not explicitly permitted |
| 0 | Table-miss | Sends unmatched packets to controller |

Higher priority wins. The isolation rule at 65535 overrides everything else, including essential services.
