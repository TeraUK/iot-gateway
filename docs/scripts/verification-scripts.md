# Verification scripts

These scripts where created at the end of each stage of development to verify that all new components where running correctly. 

The scripts where then used to create health-check.sh, a comprehensive scripts that verifiers all critical components. See [health-check.sh](health-check.md).

## verify-phase1.sh

**Purpose:** Confirms that Phase 1 (DNS filtering and logging) is correctly deployed. Run this at the end of Phase 1 setup and again any time DNS filtering behaviour seems wrong.

```bash
sudo ./scripts/verify-phase1.sh
```

**What it checks:**

| Section | What passes |
|---------|-------------|
| AdGuard Home container | Container is running with IP `172.20.0.53` |
| DNSSEC validation | `enable_dnssec: true` is present in `AdGuardHome.yaml` |
| DNS blocklists | At least 7 blocklist URLs are configured |
| DNS resolution | `google.com` resolves successfully via `192.168.50.1:53` |
| DNS blocking | `doubleclick.net` returns `0.0.0.0` or `NXDOMAIN` |
| nftables DNS interception | The DNAT rule redirecting port 53 to `172.20.0.53` is active |
| DNS-over-TLS blocking | nftables drops `tcp dport 853` from the IoT subnet |
| DNS-over-QUIC blocking | nftables drops `udp dport 8853` from the IoT subnet |
| Zeek logging | The Zeek container is running and producing log files |
| hostapd | hostapd is active and `wlp3s0` is in the OVS bridge |
| dnsmasq | dnsmasq is running and has a DHCP listener on port 67 |
| Log maintenance cron | The daily log-maintenance cron job is installed for root |

**Exit codes:** `0` if all critical checks pass, `1` if any `FAIL` items are present. `WARN` items do not cause a non-zero exit.

**Common failures and fixes:**

- `AdGuard Home container is not running` - run `docker compose up -d` and check `docker logs adguard-home` for startup errors.
- `DNS DNAT rule not found` - the nftables ruleset is not loaded. Run `sudo systemctl start nftables` and verify with `sudo nft list ruleset`.
- `doubleclick.net resolved to <IP>` - the blocklist has not synchronised yet. Open the AdGuard admin UI at `http://<host>:8088`, go to Filters, and trigger a manual update.
- `Log maintenance cron job not found` - install it with `sudo crontab -e` and add `0 3 * * * /usr/local/bin/log-maintenance.sh >> /var/log/gateway-maintenance.log 2>&1`. The `install.sh` script does this automatically.

---

## verify-phase2.sh

**Purpose:** Confirms that Phase 2 (micro-segmentation and essential services) is correctly deployed. Run this after Ryu has connected to OVS for the first time and again after any change to the gateway policy or OVS configuration.

```bash
sudo ./scripts/verify-phase2.sh
```

**What it checks:**

| Section | What passes |
|---------|-------------|
| Ryu container | Container is running and the gateway policy app has installed rules |
| Policy REST API | `/policy/status` responds, OVS switch is connected, rules are installed |
| OVS flow rules | Default deny (priority 1), ARP (priority 200), DHCP (priority 200), DNS (priority 200), NTP (priority 200), anti-lateral-movement (priority 150), and general WAN access (priority 50) rules are all present |
| OVS configuration | Fail mode is `standalone`, controller is set to `tcp:127.0.0.1:6653` |
| Connectivity | DNS resolution works from the gateway host |
| Micro-segmentation | No WiFi-to-WiFi forwarding rules exist; anti-lateral rule has DROP action at priority 150 |

**Exit codes:** `0` if all critical checks pass, `1` if any `FAIL` items are present.

**Common failures and fixes:**

- `OVS switch is NOT connected to Ryu` - Ryu may still be initialising. Wait 30 seconds and re-run. If it persists, check `docker logs ryu-controller` for errors. Verify the controller is set with `ovs-vsctl get-controller br0`.
- `Proactive rules are NOT installed` - the gateway policy app started but the OVS connection was not established when Ryu tried to install rules. Restart the Ryu container: `docker compose restart ryu`.
- `Default deny rule not found` - the flow table is in an unexpected state. Check `sudo ovs-ofctl dump-flows br0 -O OpenFlow13` for the full rule set and restart Ryu if rules are missing.
- `WiFi port was not discovered` - `wlp3s0` is not in the OVS bridge. Add it with `sudo ovs-vsctl add-port br0 wlp3s0`.

---

## verify-phase3.sh

**Purpose:** Confirms that Phase 3 (per-device destination allowlists) is correctly deployed. Run this after loading device profiles into Ryu and switching to enforcing mode.

```bash
sudo ./scripts/verify-phase3.sh
```

**What it checks:**

| Section | What passes |
|---------|-------------|
| Ryu container | Container is running and policy rules are installed |
| Policy REST API | `/policy/status` responds with switch connected and rules installed |
| Allowlist configuration | Enforcement mode is `learning` or `enforcing`; at least one device profile is loaded; DNS cache has entries |
| Allowlist REST endpoints | `GET /policy/allowlists`, `POST /policy/allowlists/reload`, `GET /policy/dns-cache`, and `GET /policy/denied-log` all respond |
| OVS intercept rules | Per-device intercept rules are present at priority 100 (enforcing mode only) |
| Config file | `device_profiles.json` is mounted inside the Ryu container |
| DNS cache updater | `dns-cache-updater.service` is running |
| DNS connectivity | `google.com` resolves from the host via AdGuard |

**Exit codes:** `0` if all critical checks pass, `1` if any `FAIL` items are present.

**Common failures and fixes:**

- `No device profiles loaded` - `device_profiles.json` is missing or empty. Generate it with `profile_builder.py` (see below), review it, then reload with `curl -X POST http://127.0.0.1:8080/policy/allowlists/reload`.
- `DNS cache is empty` - the `dns-cache-updater.service` is not running or Zeek has not yet produced DNS log entries. Check with `sudo systemctl status dns-cache-updater` and `sudo journalctl -u dns-cache-updater -n 50`.
- `dns-cache-updater service is not installed` - run `sudo ./install.sh` to deploy the service, or install it manually following the instructions in `Services/dns-cache-updater/DNS-Cache-Updater.md`.

---

## verify-phase4.sh

**Purpose:** Confirms that Phase 4 (detection scripts and automated isolation) is correctly deployed. Run this after the Zeek detection scripts are loaded and the Ryu isolation API is reachable from Zeek.

```bash
sudo ./scripts/verify-phase4.sh
```

**What it checks:**

| Section | What passes |
|---------|-------------|
| Zeek container | Container is running with no errors in recent logs |
| Detection scripts | All seven scripts are present in `/usr/local/zeek/share/zeek/site/iot-detection/` inside the container |
| IOC files | `known-bad-ips.dat` and `known-bad-domains.dat` are present in `iot-iocs/` |
| Alert log | `iot_alerts.log` exists and contains valid JSON (if any alerts have fired) |
| Ryu isolation endpoint | `POST /policy/isolate` and `POST /policy/release` respond |
| OVS mirror port | `zeek-veth-h` exists on the host, is an OVS port, and the `zeek-mirror` OVS mirror is configured |
| Zeek to Ryu connectivity | Zeek container can reach the Ryu REST API via the Docker network |

**Exit codes:** `0` if all critical checks pass, `1` if any `FAIL` items are present.

**Common failures and fixes:**

- `iot-detection directory not found` - the Zeek container started before the volume mount was ready. Restart Zeek: `docker compose restart zeek`.
- `Host-side veth (zeek-veth-h) not found` - the Zeek mirror service has not attached the veth pair. Check `sudo systemctl status zeek-mirror` and `sudo journalctl -u zeek-mirror -n 50`.
- `OVS mirror not configured` - the zeek-mirror service ran but the OVS mirror creation failed. Check `ovs-vsctl list mirror` and restart the service: `sudo systemctl restart zeek-mirror`.
- `POST /policy/isolate is not responding` - Ryu is not running or its REST API is not accessible. Check `docker logs ryu-controller`.

---
