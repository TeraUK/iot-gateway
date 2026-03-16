# dnsmasq

dnsmasq provides DHCP services for the IoT subnet. Its DNS resolver is deliberately disabled -all DNS is handled by AdGuard Home. dnsmasq's only job here is to assign IP addresses to devices joining `IoT-Security-AP` and to advertise the gateway as their default route and DNS server.

## Role in the architecture

When an IoT device connects to the WiFi network and broadcasts a DHCP Discover, OVS permits DHCP traffic to `192.168.50.1` via a priority-200 essential services rule. dnsmasq listens on the `br0` interface at that address, assigns a lease from the `192.168.50.50–150` range, and tells the device:

- its IP address and subnet mask
- its default gateway (`192.168.50.1`)
- its DNS server (`192.168.50.1`)

The DNS server address points at the gateway itself, not directly at AdGuard. When the device sends a DNS query to `192.168.50.1:53`, nftables intercepts it in the prerouting chain and redirects it to AdGuard at `172.20.0.53:53`. The device is unaware of this redirection.

dnsmasq also maintains the lease file at `/var/lib/misc/dnsmasq.leases`. This file is the primary source of IP-to-MAC address mappings used by `profile_builder.py` and the ML pipeline.

## Why DNS is disabled

dnsmasq is capable of acting as a DNS resolver, but enabling it would create a conflict with AdGuard's port 53 listener on `192.168.50.1`. Setting `port=0` completely disables dnsmasq's DNS listener, leaving AdGuard as the sole DNS service on the gateway. This also prevents dnsmasq from forwarding any DNS queries to upstream resolvers that might bypass AdGuard's blocklists.

## Configuration

The configuration file is at `config/dnsmasq/dnsmasq.conf` in the repository and is copied to `/etc/dnsmasq.conf` by `install.sh`.

### Active settings

| Setting | Value | Purpose |
|---------|-------|---------|
| `interface` | `br0` | Listen on the OVS bridge internal port |
| `bind-interfaces` | (flag) | Bind strictly to the specified interface only |
| `dhcp-range` | `192.168.50.50,192.168.50.150,255.255.255.0,24h` | DHCP pool -101 addresses, 24-hour lease time |
| `dhcp-option=option:router` | `192.168.50.1` | Default gateway advertised to clients |
| `dhcp-option=option:dns-server` | `192.168.50.1` | DNS server advertised to clients (intercepted by nftables to AdGuard) |
| `port` | `0` | DNS listener disabled |
| `domain-needed` | (flag) | Do not forward plain hostnames (no dot) to upstream |
| `bogus-priv` | (flag) | Do not forward RFC1918 reverse lookups |
| `domain` | `iot.local` | Local domain suffix assigned to DHCP clients |
| `no-resolv` | (flag) | Do not read `/etc/resolv.conf` for upstream servers |
| `log-queries` | (flag) | Log all DNS queries to syslog (useful during setup; can be disabled in production) |
| `log-dhcp` | (flag) | Log all DHCP events to syslog |

### Systemd startup ordering

The `config/dnsmasq/override.conf` drop-in ensures dnsmasq does not start until both `ovs-vswitchd` and `hostapd` are ready. This is required because dnsmasq binds to `br0`, which depends on OVS, and DHCP responses need to reach clients via the WiFi interface that hostapd manages.

```ini
[Unit]
After=hostapd.service ovs-vswitchd.service
Requires=ovs-vswitchd.service
```

This file is installed to `/etc/systemd/system/dnsmasq.service.d/override.conf` by `install.sh`.

## DHCP address assignment

IoT devices receive addresses from the `192.168.50.50–192.168.50.150` range. The gateway itself holds `192.168.50.1` as a static address on the OVS internal port (`br0`) -this address is never part of the DHCP pool.

The lease time is 24 hours. A device that is powered off and back on within 24 hours will normally receive the same IP address (dnsmasq prefers to renew the previous lease for a returning MAC address), which keeps Zeek's IP-to-MAC mappings stable.

### Assigning a fixed IP to a specific device

To give a specific device a predictable IP address, add a `dhcp-host` directive to `/etc/dnsmasq.conf`:

```bash
# Fixed IP by MAC address
dhcp-host=aa:bb:cc:dd:ee:ff,192.168.50.51
```

The address must be within the `192.168.50.0/24` subnet but does not need to be within the `50–150` pool range. After editing, restart dnsmasq:

```bash
sudo systemctl restart dnsmasq
```

## Lease file

dnsmasq writes all active DHCP leases to `/var/lib/misc/dnsmasq.leases`. The format is one lease per line:

```
<expiry epoch> <mac> <ip> <hostname> <client-id>
```

Example:

```
1742167200 aa:bb:cc:dd:ee:ff 192.168.50.75 living-room-camera *
1742167800 11:22:33:44:55:66 192.168.50.76 * *
```

This file is the input to `profile_builder.py` via the `--leases` flag. The ML pipeline also reads it during startup to populate its initial IP-to-MAC table.

## Useful commands

```bash
# Check dnsmasq is running
sudo systemctl status dnsmasq

# View active leases
cat /var/lib/misc/dnsmasq.leases

# Count active leases
wc -l < /var/lib/misc/dnsmasq.leases

# Follow DHCP events in real time
sudo journalctl -fu dnsmasq

# View recent DHCP events from syslog
grep dnsmasq /var/log/syslog | tail -30

# Confirm DNS is disabled and DHCP is listening
ss -ulnp | grep :67
ss -ulnp | grep :53   # Should show nothing for dnsmasq

# Reload configuration (picks up dhcp-host changes; no lease disruption)
sudo systemctl reload dnsmasq

# Full restart (active leases are preserved in the lease file)
sudo systemctl restart dnsmasq
```

## Troubleshooting

**Device not receiving a DHCP lease:** confirm dnsmasq is running and listening on port 67 (`ss -ulnp | grep :67`). Check that the device is associated with `IoT-Security-AP` (use `iw dev wlp3s0 station dump`) and that OVS has the DHCP permit rules installed (`sudo ovs-ofctl dump-flows br0 -O OpenFlow13 | grep tp_dst=67`).

**Lease pool exhausted:** the pool holds 101 addresses (`50–150`). If more than 101 devices are simultaneously active, new devices will not receive leases. Expand the range in `dnsmasq.conf` (e.g. to `192.168.50.50,192.168.50.200`) and restart dnsmasq.

**IP changes between reboots confusing the ML pipeline:** this typically happens when a device was offline long enough for its lease to expire before it reconnected. The ML pipeline resolves IPs to MACs dynamically from `dhcp.log`, so it will self-correct within one scoring cycle after the device reconnects and renews its lease.
