# Device Onboarding

Adding a new IoT device involves connecting it to the network, observing its traffic during a baseline period, and then creating an allowlist profile that restricts it to its legitimate destinations.

## Step 1 - Connect the device

Connect the device to `IoT-Security-AP` using the WPA2-PSK credentials. It will receive a DHCP lease from dnsmasq in the `192.168.50.50–150` range.

Find its MAC address from the DHCP lease file:

```bash
cat /var/lib/misc/dnsmasq.leases
# Format: <expiry> <mac> <ip> <hostname> <client-id>
```

Or from the Ryu API (the device appears as a known device once it has sent traffic):

```bash
curl -s http://127.0.0.1:8080/policy/devices | python3 -m json.tool
```

## Step 2 - Baseline period

Leave the device in operation during Phase 2 (general WAN access, no per-device enforcement) for at least several days, ideally covering its full usage cycle. During this time Zeek logs all its connections and DNS queries.

Things to do during the baseline period:

- Use the device normally. Run any setup or onboarding flows.
- If the device has a companion app, use it on a regular schedule.
- Check AdGuard's query log to see what domains the device queries.

## Step 3 - Generate a draft profile

`scripts/profile_builder.py` reads the Zeek logs and generates a draft `device_profiles.json` entry:

```bash
python3 scripts/profile_builder.py \
    --zeek-dir /var/lib/docker/volumes/iot-gateway_zeek-logs/_data \
    --leases /var/lib/misc/dnsmasq.leases \
    --mac aa:bb:cc:dd:ee:ff \
    --output /tmp/draft_profile.json \
    --min-connections 2
```

The `--min-connections` flag filters out destinations seen only once, reducing noise from one-off CDN requests or update checks.

Inspect the output carefully. The tool generates:

- `allowed_domains` - domain names resolved by the device via DNS.
- `allowed_cidrs` - IP addresses the device connected to directly without DNS resolution (added as `/32` entries).

## Step 4 - Review and edit the profile

The draft profile will contain some noise. Review it against the AdGuard query log and consider removing:

- Ad and analytics domains that AdGuard may not yet have blocked.
- CDN endpoints with rotating IPs (use CIDR ranges if the provider publishes them, or accept the domain-based approach).
- Domains queried only once that look like one-off initialisation calls.

Example profile entry:

```json
{
  "aa:bb:cc:dd:ee:ff": {
    "name": "Smart Thermostat - Living Room",
    "allowed_domains": [
      "api.ecobee.com",
      "auth.ecobee.com",
      "0.pool.ntp.org",
      "1.pool.ntp.org"
    ],
    "allowed_cidrs": []
  }
}
```

NTP domains are typically not needed in the allowlist because NTP is permitted at the OVS level by the essential services rules. Include them only if the device uses a vendor-specific NTP server that falls outside the `pool.ntp.org` ranges.

## Step 5 - Apply the profile

Copy the new entry into `ryu/config/device_profiles.json` and reload:

```bash
curl -X POST http://127.0.0.1:8080/policy/allowlists/reload
```

Ryu confirms the number of profiles loaded. The device is now profiled but still in `learning` mode (general WAN access) unless enforcing mode is active globally.

## Step 6 - Test before enforcing

Before switching to enforcing mode for the device, verify the allowlist is complete by monitoring the denied log. Make sure the device can reach all its required destinations:

```bash
# Watch for denied connections from this device
watch -n 5 'curl -s http://127.0.0.1:8080/policy/denied-log | \
  python3 -c "import sys,json; d=json.load(sys.stdin); \
  [print(e[\"ts\"], e[\"dst_ip\"]) for e in d[\"entries\"] \
   if e[\"mac\"]==\"aa:bb:cc:dd:ee:ff\"]"'
```

Add any denied destinations to the profile and reload until the denied log is quiet.

## Step 7 - Enable enforcing mode

Once the allowed list is complete and the denied log is quiet:

```bash
curl -X POST http://127.0.0.1:8080/policy/allowlists/mode \
     -H 'Content-Type: application/json' \
     -d '{"mode": "enforcing"}'
```

This applies to all profiled devices. Unprofiled devices continue to get general WAN access.

## Updating an existing profile

If a device receives a firmware update and starts contacting new destinations, it will appear in the denied log. Add the new destinations to the profile and reload:

```bash
# Edit ryu/config/device_profiles.json
# Then reload without restart
curl -X POST http://127.0.0.1:8080/policy/allowlists/reload
```
