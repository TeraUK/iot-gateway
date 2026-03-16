## health-check.sh

**Purpose:** A broader post-deployment and post-reboot check that covers all system components end-to-end. While the phase verify scripts each focus on the requirements of their respective phase, this script checks the full running state of the gateway and is the right thing to run after a reboot or after making changes.

```bash
sudo ./scripts/health-check.sh
```

**What it checks:**

| Section | Covers |
|---------|--------|
| Network interfaces | `enp2s0` has a WAN IP; `wlp3s0` is up |
| Open vSwitch | `ovs-vswitchd` is running; `br0` exists with `192.168.50.1`; `wlp3s0` is a port; controller is connected; fail mode is set |
| OVS flow rules | Default deny, ARP, DHCP, DNS, NTP, anti-lateral-movement, and general WAN rules are all present; isolation rules at priority 65535 if any devices are isolated |
| IP forwarding and nftables | IPv4 forwarding is enabled; nftables is active; NAT masquerade and DNS DNAT rules are loaded |
| Docker engine | Docker daemon is running |
| Ryu SDN controller | Container is running; REST API is responding; OVS switch is connected |
| AdGuard Home | Container is running; IP is `172.20.0.53`; DNS listener is active on port 53 |
| Zeek | Container is running; `zeek-eth1` mirror interface is present inside the container; host-side veth and OVS mirror are configured; log files are being written |
| Zeek mirror service | `zeek-mirror.service` is active and enabled |
| ML pipeline | Container is running; Zeek logs volume is mounted |
| hostapd | Running; `hostapd.conf` exists; PSK file has correct permissions (600) |
| dnsmasq | Running; DHCP listener is active on port 67; `port=0` is set (DNS disabled) |
| Log maintenance cron | The daily cron job is installed |

The health check is read-only and makes no changes to the system.

**Exit codes:** `0` if all critical checks pass, `1` if any `FAIL` items are present. `WARN` items indicate configuration concerns but do not cause failure.

---