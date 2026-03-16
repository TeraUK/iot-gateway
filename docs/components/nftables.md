# nftables

nftables is the Linux kernel packet filtering framework used by the gateway to enforce three specific policies that sit outside what OVS handles: NAT masquerade for outbound IoT traffic, forced DNS interception, and blocking of encrypted DNS bypass protocols.

## Role in the architecture

OVS handles all L2 forwarding decisions within the IoT subnet. nftables operates at the L3/L4 level on the host IP stack and handles the policies that require kernel NAT and connection tracking -capabilities that are outside OVS's scope.

The division of responsibility is:

| Policy | Enforced by |
|--------|------------|
| Micro-segmentation (IoT-to-IoT blocking) | OVS OpenFlow rules |
| Per-device destination allowlists | OVS + Ryu |
| Device isolation | OVS (priority-65535 DROP rule) |
| NAT masquerade (IoT to internet) | nftables postrouting |
| DNS interception (all devices, including hardcoded resolvers) | nftables prerouting DNAT |
| DoT/DoQ blocking | nftables forward chain |
| IP forwarding between `br0` and `enp2s0` | `net.ipv4.ip_forward` sysctl, enabled persistently |

## Ruleset

The complete ruleset is at `config/nftables/nftables.conf` in the repository and is copied to `/etc/nftables.conf` by `install.sh`. The `flush ruleset` at the top clears any previously loaded rules before applying the gateway's rules, ensuring a clean known state on every load.

### `table inet filter` -packet filtering

```nftables
table inet filter {
    chain input {
        type filter hook input priority 0; policy accept;
    }

    chain forward {
        type filter hook forward priority 0; policy accept;

        iifname "br0" ip saddr 192.168.50.0/24 tcp dport 853
            counter log prefix "IOT-DOT-BLOCKED: " drop

        iifname "br0" ip saddr 192.168.50.0/24 udp dport 8853
            counter log prefix "IOT-DOQ-BLOCKED: " drop
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
```

The `input` and `output` chains accept all traffic. Policy enforcement in those directions is delegated to OVS and the host's existing security posture. The `forward` chain contains two active rules:

**DNS-over-TLS blocking (port 853):** IoT devices have no legitimate reason to contact port 853 on any external server -all DNS must flow through AdGuard via the DNAT rule. Any device attempting DoT is either misconfigured or attempting to bypass filtering. The `counter` keyword accumulates packet and byte counts, and the `log` prefix writes the event to the kernel log as `IOT-DOT-BLOCKED:`, allowing analysis of which devices are attempting DoT bypass.

**DNS-over-QUIC blocking (port 8853):** same rationale as DoT. QUIC-based encrypted DNS uses port 8853 and would allow a device to bypass AdGuard if not blocked.

**Why DoH is not blocked here:** DNS-over-HTTPS runs on port 443, which is the same port used for all HTTPS traffic. Blocking port 443 would break IoT device internet access entirely. Instead, DoH bypass is addressed indirectly by per-device allowlists in Ryu (Phase 3): a device restricted to its manufacturer's API servers cannot reach a public DoH resolver such as `1.1.1.1` or `dns.google` because those IPs will not be in its allowlist.

### `table ip nat` -NAT and DNS interception

```nftables
table ip nat {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;

        iifname "br0" ip saddr 192.168.50.0/24
            ip daddr != 192.168.50.1 udp dport 53
            dnat to 172.20.0.53

        iifname "br0" ip saddr 192.168.50.0/24
            ip daddr != 192.168.50.1 tcp dport 53
            dnat to 172.20.0.53
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;

        oifname "enp2s0" ip saddr 192.168.50.0/24 masquerade
    }
}
```

**DNS DNAT (prerouting):** any UDP or TCP packet destined for port 53 that originates from the IoT subnet (`192.168.50.0/24`) and is not already addressed to the gateway itself (`ip daddr != 192.168.50.1`) is redirected to AdGuard at `172.20.0.53:53`. This rule fires before routing, so the device's intended DNS destination is silently replaced. A device with a hardcoded resolver of `8.8.8.8`, `1.1.1.1`, or any other address will have its DNS queries answered by AdGuard without any indication that a redirect occurred.

The exclusion of `192.168.50.1` as a destination prevents the rule from redirecting queries that are correctly addressed to the gateway itself (the advertised DNS server from DHCP), which would create a redirect loop.

**NAT masquerade (postrouting):** traffic from the IoT subnet leaving via `enp2s0` (the WAN interface) has its source address replaced with the WAN IP of `enp2s0`. This is standard SNAT masquerade -the upstream router sees only the gateway's WAN address, not the individual IoT device IPs.

## IP forwarding

nftables NAT requires the host kernel to forward packets between interfaces. This is enabled persistently via a sysctl.d file written by `install.sh`:

```
# /etc/sysctl.d/99-iot-gateway.conf
net.ipv4.ip_forward = 1
```

Without this setting the kernel would drop packets attempting to transit from `br0` to `enp2s0` and IoT devices would have no internet access.

## Verifying the ruleset

```bash
# Show the full loaded ruleset
sudo nft list ruleset

# Confirm the DNAT rule is active
sudo nft list ruleset | grep "dnat to"

# Confirm the masquerade rule is active
sudo nft list ruleset | grep masquerade

# Confirm IPv4 forwarding is enabled
cat /proc/sys/net/ipv4/ip_forward   # Should return 1

# View DoT/DoQ block event counters
sudo nft list ruleset | grep -A2 "IOT-DO"

# View recent block events in the kernel log
sudo grep -E "IOT-DO[TQ]-BLOCKED" /var/log/syslog | tail -20
```

## Reloading the ruleset

The nftables service reloads `/etc/nftables.conf` on boot. To apply changes immediately without rebooting:

```bash
sudo systemctl restart nftables
```

Because the ruleset starts with `flush ruleset`, the reload is atomic: the old rules are cleared and the new rules take effect in a single operation. There is a brief window during the flush where no rules are loaded, so avoid reloading during active traffic if possible.

## Relationship to OVS

nftables and OVS process packets at different points in the Linux networking stack. OVS intercepts packets at the bridge level before they reach the host IP stack. nftables hooks run on the host IP stack after OVS has forwarded a packet via `OFPP_LOCAL` (the OVS internal port, which is `br0` from the host's perspective).

The traffic flow for an outbound IoT packet is:

```
IoT device → wlp3s0 (OVS port)
    → OVS evaluates OpenFlow rules
    → OFPP_LOCAL (forward to host IP stack)
    → nftables prerouting (DNS DNAT if applicable)
    → routing
    → nftables postrouting (NAT masquerade)
    → enp2s0 → internet
```

This means OVS must permit the packet before nftables can process it. If OVS drops a packet (default deny, or a device isolation rule), nftables never sees it.
