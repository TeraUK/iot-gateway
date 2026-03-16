# AdGuard Home

AdGuard Home provides DNS filtering (POL-03). It runs as a Docker container with a static IP (`172.20.0.53`) so that the nftables DNAT rule can always target it reliably.

## Role in the architecture

AdGuard sits at the end of the nftables DNAT chain. Every DNS query from an IoT device - regardless of the target DNS server configured on the device - is redirected to `172.20.0.53:53` by nftables before leaving the host. AdGuard then:

1. Checks the query against its blocklists.
2. If blocked, returns `0.0.0.0` (or NXDOMAIN depending on configuration).
3. If not blocked, forwards to the configured upstream resolver (DNS-over-HTTPS or DNS-over-TLS) and returns the result.

This means devices with hardcoded DNS servers (`8.8.8.8`, `1.1.1.1`, etc.) are silently served by AdGuard rather than their intended resolver. They will never know they are being filtered.

## DNS-over-TLS and DNS-over-QUIC blocking

Devices cannot bypass AdGuard by using encrypted DNS protocols directly:

- **DoT (port 853)** - blocked by nftables `tcp dport 853 drop`
- **DoQ (port 8853)** - blocked by nftables `udp dport 8853 drop`

DoH (DNS-over-HTTPS, port 443) cannot be blocked without disrupting legitimate HTTPS traffic. However, since all HTTPS traffic passes through the allowlist and nftables NAT, and since allowed DoH providers would need to be in a device's allowlist, this is an acceptable limitation.

## Blocklist configuration

I use a combination of:

- **General ad and tracking blocklists** - block analytics, advertising, and fingerprinting domains across all devices.
- **IoT-specific blocklists** - target manufacturer telemetry, firmware phone-home domains, and analytics endpoints commonly used by consumer IoT devices.
- **Threat intelligence feeds** - include known C2 infrastructure, malware distribution, and phishing domains.

Blocklists are configured via the AdGuard admin UI at `http://<gateway-host>:8088`. They should be reviewed and updated monthly.

## Admin access

| URL | Purpose |
|-----|---------|
| `http://<host>:8088` | Admin panel (after initial setup) |
| `http://<host>:3000` | Initial setup wizard only |

The admin panel is not accessible from the IoT subnet (`192.168.50.0/24`). It is only reachable from the host itself or from a separate management network.

## Query log retention

The query log is configured for 90-day retention (`2160h`) in `adguard/conf/AdGuardHome.yaml`, matching the overall 90-day log retention policy (NFR-07).

## Verifying DNS interception

From a connected IoT device (or a device simulating one):

```bash
# Query using a hardcoded external DNS server - should still be blocked
dig @8.8.8.8 doubleclick.net

# Should return 0.0.0.0 or NXDOMAIN (blocked by AdGuard)
dig @192.168.50.1 doubleclick.net

# Legitimate domain should resolve
dig @192.168.50.1 google.com
```

From the gateway host, verify the DNAT rule is active:

```bash
sudo nft list ruleset | grep "dnat to 172.20.0.53"
```
