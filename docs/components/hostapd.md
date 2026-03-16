# hostapd

hostapd is the WiFi access point daemon. It manages the `wlp3s0` wireless radio and is responsible for IEEE 802.11 association, WPA2-PSK authentication, and client isolation. It is the entry point for every IoT device joining the network.

## Role in the architecture

hostapd sits at the very edge of the security perimeter. Its job is narrow but critical: decide which devices are allowed to associate with the network at all, before any other security layer is involved. A device that cannot pass WPA2 authentication never enters the OVS data plane.

Once a device authenticates, hostapd bridges `wlp3s0` into the OVS bridge `br0`. From that point all of the device's traffic enters the OpenFlow pipeline and is subject to Ryu's flow rules -hostapd hands off and has no further involvement in forwarding decisions.

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

The WiFi passphrase is stored separately from `hostapd.conf` in `/etc/hostapd/hostapd.psk`. This separation means the configuration file can be committed to version control and shared without exposing the passphrase.

The file format is one entry per line:

```
<MAC address> <passphrase>
```

The wildcard MAC address `00:00:00:00:00:00` applies the passphrase to all connecting clients. Per-device passphrases can be added by replacing the wildcard with a specific MAC address.

```bash
# Correct permissions are critical -this file contains a credential
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

`ap_isolate=1` instructs hostapd to enable intra-BSS station isolation. When active, the AP drops any 802.11 frame where both the originating station and the destination station are associated with the same BSS -in other words, it prevents WiFi clients from sending frames directly to each other through the access point.

This operates entirely at the 802.11 driver level, before OVS is involved. When a device sends a frame and the destination MAC address belongs to another device currently associated with `IoT-Security-AP`, the nl80211 driver discards the frame immediately. The frame is never delivered to the `wlp3s0` port on the OVS bridge and OVS never processes it.

### Why it is necessary alongside the OVS anti-lateral-movement rule

The OVS anti-lateral-movement rule (priority 150) drops any IPv4 packet arriving from `wlp3s0` that is destined for the IoT subnet (`192.168.50.0/24`). This blocks routed lateral movement -a device trying to reach another device by sending traffic via the gateway IP. However, the anti-lateral-movement rule cannot catch direct WiFi-to-WiFi frames that never pass through the OVS IP stack at all.

Without `ap_isolate`, Device A could send a raw L2 frame addressed directly to Device B's MAC address. That frame would arrive at OVS on the `wlp3s0` port, be matched against the flow table, and potentially be forwarded out the same `wlp3s0` port back to Device B. The anti-lateral-movement rule only matches on `eth_type=0x0800` (IPv4), so raw ARP or other non-IP frames addressed to another device would not be caught by it. ARP in particular is a meaningful gap: without isolation a device could ARP for another device, receive its IP, and then use raw IP to communicate with it directly at L2 before OVS's IPv4 rules become relevant.

`ap_isolate` closes this by making the question moot: the driver never delivers the frame to OVS in the first place. Together, the two controls form a complete barrier:

| Attack vector | Blocked by |
|--------------|-----------|
| Device A routes packets via gateway to Device B (L3) | OVS anti-lateral-movement rule (priority 150) |
| Device A sends raw L2 frames directly to Device B | `ap_isolate=1` at the 802.11 driver level |
| Device A ARPs for Device B, then sends direct IP | `ap_isolate=1` prevents the ARP response from reaching Device A |

### Why ap_isolate prevents granular per-device micro-segmentation

`ap_isolate` is a binary, BSS-wide setting. It is either on -in which case no WiFi client can communicate with any other WiFi client directly -or off, in which case all clients can potentially reach each other through the AP. There is no built-in hostapd mechanism to say "allow Device A to reach Device B but not Device C."

This is the core limitation for granular per-device micro-segmentation. In the gateway's current architecture, `wlp3s0` is a single OVS port. All IoT devices, regardless of their individual identity, enter OVS through that same port. OVS does know the source MAC address of every frame, so it can apply per-device rules for WAN-bound traffic (which is how per-device allowlists work for Phase 3). But for WiFi-to-WiFi traffic, the situation is different: if `ap_isolate` is disabled, whether a frame between two associated stations is delivered to the OVS bridge at all depends on the WiFi driver's behaviour -and on the reference hardware (`wlp3s0`, nl80211 driver, Intel i5-12500T), intra-BSS frames are handled internally by the driver and are not reliably delivered to the bridge. This was confirmed during Phase 3 development: disabling `ap_isolate` and relying on OVS rules alone to enforce device isolation did not work because OVS was not consistently receiving the frames.

The result is an all-or-nothing choice at the WiFi layer: either block all device-to-device WiFi traffic with `ap_isolate=1`, or allow it all and depend entirely on OVS rules that may not reliably see the traffic. Given that the primary threat model for this gateway is IoT device lateral movement, `ap_isolate=1` is the correct choice. Granular control -permitting some device pairs to communicate while blocking others -is not achievable without changes to how the WiFi interface is presented to OVS.

### What would be required to achieve granular per-device control

The root cause of the limitation is that all IoT devices share a single OVS port (`wlp3s0`). For OVS to enforce per-pair policies, each device would need to appear on a distinct OVS port, giving Ryu the port-level visibility it needs to install targeted forwarding rules.

There are two architectural paths that would achieve this:

**Option 1: Per-station virtual interfaces (4-address / WDS mode)**

In this mode, hostapd creates a dedicated virtual network interface for each associated station -for example, `wlp3s0.sta_aa_bb_cc_dd_ee_ff`. Each of these virtual interfaces would be added to the OVS bridge as its own port. OVS would then see each device on a distinct port number, and Ryu could install per-pair rules such as "allow port 3 (Device A) to output to port 5 (Device B) but drop all other inter-device traffic."

Enabling this requires:

- Setting `wds_sta=1` in `hostapd.conf` to enable per-station 4-address mode.
- The nl80211 driver and the specific WiFi chipset supporting per-station virtual interface creation. Not all hardware supports this.
- The IoT client devices themselves supporting 4-address 802.11 frames. Consumer IoT devices almost universally do not -4-address mode is primarily used for wireless mesh backhaul between APs, not for client associations. This is the decisive hardware limitation. Even if the gateway hardware supported per-station VIFs, the IoT devices would reject the 4-address frames and fail to associate.

**Option 2: Per-client dynamic VLAN assignment**

hostapd supports assigning each associated station to a VLAN at association time via the `per_sta_vif=1` option or via a RADIUS server returning a VLAN attribute. Each VLAN would appear as a tagged sub-interface on the bridge (e.g. `wlp3s0.100`, `wlp3s0.101`), again giving each device a distinct bridge interface and therefore a distinct OVS port.

This approach does not require client-side support for 4-address frames. However:

- `per_sta_vif=1` requires the driver to support dynamic per-station interface creation, which is driver and firmware dependent. Testing on the reference hardware confirmed that this is not reliably supported on `wlp3s0` with the nl80211 driver.
- VLAN-based assignment via RADIUS would require running a RADIUS server and configuring MAC-based authentication, adding significant operational complexity.

**Option 3: Hardware access point**

Enterprise and prosumer access points -devices such as the Ubiquiti UniFi range -typically expose each associated client as a separate bridge interface, or support per-client VLAN tagging natively, without the driver limitations of an embedded WiFi radio. Replacing `wlp3s0` with a hardware AP connected to the host via Ethernet (and adding that Ethernet interface to the OVS bridge instead) would sidestep the driver constraint entirely. The hardware AP would handle the 802.11 layer and present each device as a standard Ethernet frame source, which OVS handles correctly.

This is the most practical path to granular per-device WiFi control but requires additional hardware and a change to the network topology.

**Summary of the limitation**

The requirement for granular per-device communication control (allowing Device A to reach Device B while blocking Device A from Device C) is recorded as not yet implemented in the architecture overview. The current implementation provides complete isolation of all IoT devices from each other, which is the appropriate default posture for a zero-trust IoT network. If selective device-to-device communication becomes a specific requirement, Option 3 (hardware AP) is the most reliable path forward with the current system architecture.

## Security considerations

**WPA2-PSK limitations.** All IoT devices share a single passphrase. This is a practical constraint -most IoT devices do not support WPA2-Enterprise (RADIUS). If the passphrase is compromised, all devices on the network must be re-provisioned. The OVS and Ryu policy layers provide defence in depth, so a compromised passphrase does not automatically give an attacker access to other devices or the gateway itself.

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
