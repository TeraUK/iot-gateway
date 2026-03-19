# hostapd

hostapd is the WiFi access point daemon. It manages the `wlp3s0` wireless radio and is responsible for IEEE 802.11 association, WPA2-PSK authentication, and client isolation. It is the entry point for every IoT device joining the network.

## Role in the architecture

hostapd sits at the very edge of the security perimeter. Its job is narrow but critical: decide which devices are allowed to associate with the network at all, before any other security layer is involved. A device that cannot pass WPA2 authentication never enters the OVS data plane.

Once a device authenticates, hostapd bridges `wlp3s0` into the OVS bridge `br0`. From that point all of the device's traffic enters the OpenFlow pipeline and is subject to Ryu's flow rules - hostapd hands off and has no further involvement in forwarding decisions.

The `ap_isolate=1` setting in `hostapd.conf` instructs hostapd to block direct frame forwarding between associated stations at the 802.11 layer. This is a complementary control to the OVS anti-lateral-movement rule: even if an OVS misconfiguration were to allow IoT-to-IoT traffic, `ap_isolate` would block it before the frames reach OVS.

## Configuration

The configuration file is at `config/hostapd/hostapd.conf` in the repository and is copied to `/etc/hostapd/hostapd.conf` by `install.sh`.

### Active settings

| Setting | Value | Purpose |
|---------|-------|---------|
| `interface` | `wlp3s0` | WiFi radio interface managed by hostapd |
| `driver` | `nl80211` | Standard Linux wireless driver backend |
| `bridge` | `br0` | OVS bridge that associated clients are placed into |
| `ssid` | `IoT-Security-AP` | Network name visible to IoT devices |
| `hw_mode` | `g` | 2.4 GHz 802.11g mode |
| `channel` | `7` | WiFi channel |
| `ieee80211n` | `1` | 802.11n (HT) extensions enabled |
| `wmm_enabled` | `1` | Wi-Fi Multimedia QoS enabled |
| `country_code` | `GB` | Regulatory domain; sets legal channel and power limits |
| `ieee80211d` | `1` | Country information element broadcast enabled |
| `macaddr_acl` | `0` | No MAC address access control (all MACs accepted subject to WPA2) |
| `auth_algs` | `1` | Open system authentication only (WPA2 handles security) |
| `ignore_broadcast_ssid` | `0` | SSID is broadcast (visible to scanning devices) |
| `wpa` | `2` | WPA2 only; WPA1 is not permitted |
| `wpa_psk_file` | `/etc/hostapd/hostapd.psk` | Passphrase file (see below) |
| `wpa_key_mgmt` | `WPA-PSK` | Pre-shared key authentication |
| `rsn_pairwise` | `CCMP` | AES-CCMP encryption only; TKIP is not permitted |
| `ap_isolate` | `1` | Blocks direct station-to-station frame forwarding at 802.11 layer |
| `logger_syslog` | `-1` | All logging facilities sent to syslog |
| `logger_syslog_level` | `2` | INFO level and above to syslog |

### Passphrase file

The WiFi passphrase is stored separately from `hostapd.conf` in `/etc/hostapd/hostapd.psk`.

This separation means the configuration file can be committed to version control and shared without exposing the passphrase.

The file format is one entry per line:

```
<MAC address> <passphrase>
```

The wildcard MAC address `00:00:00:00:00:00` applies the passphrase to all connecting clients. Per-device passphrases can be added by replacing the wildcard with a specific MAC address.

```bash
# Correct permissions are critical - this file contains a credential
sudo chmod 600 /etc/hostapd/hostapd.psk
sudo chown root:root /etc/hostapd/hostapd.psk
```

`install.sh` creates this file interactively during setup and sets the correct permissions automatically.

### Systemd startup ordering

The `config/hostapd/override.conf` drop-in ensures hostapd does not start until `ovs-vswitchd` is ready. This is required because `wlp3s0` must be under OVS control before hostapd bridges it into `br0`.

```ini
[Unit]
After=ovs-vswitchd.service
Requires=ovs-vswitchd.service
```

This file is installed to `/etc/systemd/system/hostapd.service.d/override.conf` by `install.sh`.

## ap_isolate in depth

### What it does

`ap_isolate=1` instructs hostapd to enable intra-BSS station isolation. When active, the AP drops any 802.11 frame where both the originating station and the destination station are associated with the same BSS - in other words, it prevents WiFi clients from sending frames directly to each other through the access point.

This operates entirely at the 802.11 driver level, before OVS is involved. When a device sends a frame and the destination MAC address belongs to another device currently associated with `IoT-Security-AP`, the nl80211 driver discards the frame immediately. The frame is never delivered to the `wlp3s0` port on the OVS bridge and OVS never processes it.

### Why it is necessary alongside the OVS anti-lateral-movement rule

The OVS anti-lateral-movement rule (priority 150) drops any IPv4 packet arriving from `wlp3s0` that is destined for the IoT subnet (`192.168.50.0/24`). This blocks routed lateral movement - a device trying to reach another device by sending traffic via the gateway IP. However, the anti-lateral-movement rule cannot catch direct WiFi-to-WiFi frames that never pass through the OVS IP stack at all.

Without `ap_isolate`, Device A could send a raw L2 frame addressed directly to Device B's MAC address. That frame would arrive at OVS on the `wlp3s0` port, be matched against the flow table, and potentially be forwarded out the same `wlp3s0` port back to Device B. The anti-lateral-movement rule only matches on `eth_type=0x0800` (IPv4), so raw ARP or other non-IP frames addressed to another device would not be caught by it. ARP in particular is a meaningful gap: without isolation a device could ARP for another device, receive its IP, and then use raw IP to communicate with it directly at L2 before OVS's IPv4 rules become relevant.

`ap_isolate` closes this by making the question moot: the driver never delivers the frame to OVS in the first place. Together, the two controls form a complete barrier:

| Attack vector | Blocked by |
|--------------|-----------|
| Device A routes packets via gateway to Device B (L3) | OVS anti-lateral-movement rule (priority 150) |
| Device A sends raw L2 frames directly to Device B | `ap_isolate=1` at the 802.11 driver level |
| Device A ARPs for Device B, then sends direct IP | `ap_isolate=1` prevents the ARP response from reaching Device A |

### Granular per-device communication via lateral permits

Although `ap_isolate` is a binary, BSS-wide setting with no built-in concept of permitted pairs, selective device-to-device communication is achievable by combining it with proxy ARP on `br0` and per-pair OVS exception rules at priority 160. This approach keeps `ap_isolate=1` fully active and does not weaken the 802.11-layer barrier.

The mechanism works as follows. When a permit is granted between Device A and Device B via the REST API, Ryu installs four OpenFlow rules at priority 160, which sit above the anti-lateral-movement drop at priority 150:

- Outbound A to B: `in_port=wifi, eth_src=MAC_A, ipv4_dst=IP_B` → `OFPP_LOCAL`
- Outbound B to A: `in_port=wifi, eth_src=MAC_B, ipv4_dst=IP_A` → `OFPP_LOCAL`
- Return to A: `in_port=LOCAL, eth_dst=MAC_A, ipv4_src=IP_B` → `wifi`
- Return to B: `in_port=LOCAL, eth_dst=MAC_B, ipv4_src=IP_A` → `wifi`

Because `ap_isolate` blocks direct ARP between stations, proxy ARP must be enabled on `br0` so the kernel can answer ARP requests on behalf of each device. Two kernel settings are required:

```bash
# Allow the kernel to answer ARP requests on behalf of other devices on the subnet
sudo sysctl -w net.ipv4.conf.br0.proxy_arp=1

# Required when requester and target are both reachable via the same interface
sudo sysctl -w net.ipv4.conf.br0.proxy_arp_pvlan=1
```

Make these persistent by adding them to `/etc/sysctl.d/99-iot-gateway.conf`:

```
net.ipv4.conf.br0.proxy_arp = 1
net.ipv4.conf.br0.proxy_arp_pvlan = 1
```

With both settings active, the full packet journey for a permitted pair is:

1. Device A sends an ARP broadcast for Device B's IP. `ap_isolate` prevents it reaching Device B directly.
2. The ARP reaches `br0` via the OVS essential services ARP rule (priority 200). The kernel replies using the gateway's own MAC, telling Device A that Device B is at the gateway MAC.
3. Device A sends an IP packet to the gateway MAC with destination IP = Device B's IP. The priority-160 OVS rule forwards it to `OFPP_LOCAL`.
4. The kernel routes it back out `br0` toward Device B, using Device B's real MAC as the Ethernet destination. `ap_isolate` does not block this frame because its source is the gateway, not another station.
5. Device B's reply follows the same path in reverse.

The devices communicate entirely via the gateway as a Layer 3 relay. No direct WiFi-to-WiFi frames are exchanged at any point.

**multicast service discovery:** mDNS (port 5353) and SSDP (port 1900) are also blocked by `ap_isolate` and by the OVS default-deny rule. Devices cannot organically discover each other by hostname or service name. The administrator must know both device IP addresses before creating a permit.

See [REST API](../reference/api.md) for the lateral permit endpoint reference and [OVS and Ryu](ovs-ryu.md) for the OpenFlow rule details.

### Why a hardware access point enables full per-device granularity

The approach described above enables selective communication between explicitly permitted pairs but does not give OVS the per-device port visibility it would need for truly arbitrary per-device policies. The root cause is that all IoT devices share a single OVS port (`wlp3s0`).

A hardware AP connected to the host via Ethernet sidesteps this entirely. The AP handles the 802.11 layer internally and presents each associated client to OVS as a plain Ethernet frame source on a distinct port. OVS can then install per-pair forwarding rules without any reliance on proxy ARP or Layer 3 routing through the gateway. This is the most flexible architecture but requires additional hardware.

## Security considerations

**WPA2-PSK limitations.** All IoT devices share a single passphrase. This is a practical constraint - most IoT devices do not support WPA2-Enterprise (RADIUS). If the passphrase is compromised, all devices on the network must be re-provisioned. The OVS and Ryu policy layers provide defence in depth, so a compromised passphrase does not automatically give an attacker access to other devices or the gateway itself.

**MAC randomisation.** Many modern devices randomise their MAC address when scanning for networks or when connecting to a new network. This will cause the device to appear in `/policy/devices` under its randomised MAC, but any lateral permit or device profile created using that MAC will break when the device reconnects with a different randomised MAC. Disable MAC randomisation on devices that are to be profiled or given lateral permits. On Linux this is done per-connection:

```bash
nmcli connection modify "IoT-Security-AP" wifi.cloned-mac-address permanent
```

**Channel selection.** Channel 7 was chosen to minimise overlap with typical home router channels (1, 6, 11). If persistent interference is observed, change the `channel` value in `hostapd.conf` and restart hostapd. Refer to local regulatory limits for valid channels in your country.

**Country code.** The `country_code=GB` setting enforces UK regulatory limits on transmit power and permitted channels. Change this to the appropriate two-letter ISO 3166-1 alpha-2 code for the deployment location.

## Useful commands

```bash
# Check hostapd is running
sudo systemctl status hostapd

# View connected clients
iw dev wlp3s0 station dump

# Count connected clients
iw dev wlp3s0 station dump | grep -c Station

# View recent association events
sudo journalctl -u hostapd --since "1 hour ago"

# Reload configuration without dropping all clients (not all changes take effect this way)
sudo kill -HUP $(cat /var/run/hostapd/wlp3s0)

# Full restart (drops all connected clients briefly)
sudo systemctl restart hostapd
```

## Changing the WiFi passphrase

Edit `/etc/hostapd/hostapd.psk` and replace the passphrase, then restart hostapd. All currently connected devices will be disconnected and will need to re-authenticate with the new passphrase.

```bash
# Edit the PSK file
sudo nano /etc/hostapd/hostapd.psk

# Confirm permissions are still correct after editing
sudo chmod 600 /etc/hostapd/hostapd.psk

# Restart to apply
sudo systemctl restart hostapd
```
