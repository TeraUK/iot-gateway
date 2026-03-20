# REST API Reference

The Ryu policy application exposes a REST API on port `8080`. All endpoints return JSON. The API is used by the Zeek detection scripts, the ML pipeline, the `dns_cache_updater` service, and can be used manually for device management.

Base URL: `http://127.0.0.1:8080` (host) or `http://ryu:8080` (from containers on `gateway-net`)

---

## `GET /policy/status`

Returns the current state of the policy engine.

**curl**

```bash
curl http://127.0.0.1:8080/policy/status
```

**Response**

```json
{
    "switch_connected": true,
    "switch_dpid": 1,
    "wifi_port": 1,
    "wifi_interface": "wlp3s0",
    "rules_installed": true,
    "rule_count": 19,
    "known_devices": 4,
    "isolated_devices": 1,
    "connect_time": "2026-03-15T10:00:00+00:00",
    "gateway_ip": "192.168.50.1",
    "iot_subnet": "192.168.50.0/255.255.255.0",
    "enforcement_mode": "enforcing",
    "profiled_devices": 3,
    "dns_cache_entries": 47,
    "denied_log_size": 12,
    "lateral_permit_count": 1
}
```

`lateral_permit_count` reflects the number of active per-pair lateral movement permits currently stored in memory.

---

## `GET /policy/devices`

Returns all MAC addresses known to the policy engine. The table is pre-populated from the dnsmasq lease file at startup and updated via DHCP snooping and IPv4 packet observation at runtime.

**curl**

```bash
curl http://127.0.0.1:8080/policy/devices
```

**Response**

```json
{
    "devices": {
        "aa:bb:cc:dd:ee:ff": {
            "first_seen": "2026-03-10T08:00:00+00:00",
            "last_seen": "2026-03-15T12:30:00+00:00",
            "ip": "192.168.50.75",
            "has_profile": true,
            "profile_name": "Smart Thermostat",
            "is_isolated": false,
            "has_lateral_permit": false
        }
    },
    "total": 4
}
```

| Field | Description |
|-------|-------------|
| `ip` | Last known IP address for this device. Populated from the dnsmasq lease file, DHCP ACK snooping, or observed IPv4 packet headers. `null` if no IP has been recorded yet. |
| `has_profile` | Whether a device profile exists for this MAC in `device_profiles.json`. |
| `profile_name` | The device name from its profile, if one exists. |
| `is_isolated` | Whether a priority-65535 DROP rule is currently installed for this device. |
| `has_lateral_permit` | Whether this device participates in at least one active lateral movement permit. |

---

## `POST /policy/isolate`

Quarantine a device by MAC address. Installs a priority-65535 DROP rule for all traffic to and from that MAC. Isolation overrides all other rules including lateral permits and essential services.

**curl**

```bash
curl -X POST http://127.0.0.1:8080/policy/isolate \
  -H "Content-Type: application/json" \
  -d '{"mac": "aa:bb:cc:dd:ee:ff", "reason": "port scan detected"}'
```

**Request body**

```json
{
    "mac": "aa:bb:cc:dd:ee:ff",
    "reason": "port scan detected"
}
```

**Response (success)**

```json
{
    "success": true,
    "mac": "aa:bb:cc:dd:ee:ff",
    "isolated_at": "2026-03-15T12:35:00+00:00"
}
```

**Response (already isolated)**

```json
{
    "success": false,
    "error": "aa:bb:cc:dd:ee:ff is already isolated"
}
```

**Error responses:** `400` if `mac` field is missing or JSON is invalid. `500` if the switch is not connected.

---

## `POST /policy/release`

Remove isolation from a device. Deletes the priority-65535 DROP rules. The device returns to its normal policy (allowlist enforcement or general WAN access). Any active lateral permits for this device remain in place and take effect again immediately.

**curl**

```bash
curl -X POST http://127.0.0.1:8080/policy/release \
  -H "Content-Type: application/json" \
  -d '{"mac": "aa:bb:cc:dd:ee:ff"}'
```

**Request body**

```json
{
    "mac": "aa:bb:cc:dd:ee:ff"
}
```

**Response (success)**

```json
{
    "success": true,
    "mac": "aa:bb:cc:dd:ee:ff"
}
```

---

## `GET /policy/allowlists`

Returns all loaded device profiles and the current enforcement mode.

**curl**

```bash
curl http://127.0.0.1:8080/policy/allowlists
```

**Response**

```json
{
    "mode": "enforcing",
    "profiles": {
        "aa:bb:cc:dd:ee:ff": {
            "name": "Smart Thermostat",
            "allowed_domains": ["api.vendor.com"],
            "allowed_cidrs": []
        }
    },
    "total_profiles": 3
}
```

---

## `POST /policy/allowlists/reload`

Reload device profiles from `device_profiles.json` without restarting the container. Applies new rules immediately to the running switch.

**curl**

```bash
curl -X POST http://127.0.0.1:8080/policy/allowlists/reload
```

**Request body:** none required

**Response**

```json
{
    "success": true,
    "profiles_loaded": 3,
    "added": 1,
    "removed": 0
}
```

---

## `POST /policy/allowlists/mode`

Switch the enforcement mode between `learning` and `enforcing`.

**curl**

```bash
curl -X POST http://127.0.0.1:8080/policy/allowlists/mode \
  -H "Content-Type: application/json" \
  -d '{"mode": "enforcing"}'
```

**Request body**

```json
{
    "mode": "enforcing"
}
```

Valid values: `"learning"` or `"enforcing"`.

---

## `POST /policy/dns-cache`

Update the in-memory DNS cache with domain-to-IP mappings. Used by the `dns_cache_updater` service.

**curl**

```bash
curl -X POST http://127.0.0.1:8080/policy/dns-cache \
  -H "Content-Type: application/json" \
  -d '{"mappings": {"api.vendor.com": ["203.0.113.50", "203.0.113.51"], "cloud.vendor.com": ["198.51.100.10"]}}'
```

**Request body**

```json
{
    "mappings": {
        "api.vendor.com": ["203.0.113.50", "203.0.113.51"],
        "cloud.vendor.com": ["198.51.100.10"]
    }
}
```

---

## `GET /policy/dns-cache`

Returns the current contents of the DNS cache.

**curl**

```bash
curl http://127.0.0.1:8080/policy/dns-cache
```

---

## `GET /policy/denied-log`

Returns recent denied connection attempts from profiled devices in enforcing mode. Useful for identifying destinations to add to allowlists.

**curl**

```bash
curl http://127.0.0.1:8080/policy/denied-log
```

**Response**

```json
{
    "entries": [
        {
            "timestamp": "2026-03-15T12:30:00+00:00",
            "mac": "aa:bb:cc:dd:ee:ff",
            "dst_ip": "203.0.113.99",
            "reason": "not in allowlist for Smart Thermostat",
            "device_name": "Smart Thermostat"
        }
    ],
    "total": 1
}
```

---

## `GET /policy/lateral-permits`

Returns all active lateral movement permits. Each permit grants bidirectional unicast IP communication between two specific devices, overriding the default anti-lateral-movement policy.

**curl**

```bash
curl http://127.0.0.1:8080/policy/lateral-permits
```

**Response**

```json
{
    "permits": [
        {
            "mac_a": "aa:bb:cc:dd:ee:ff",
            "mac_b": "11:22:33:44:55:66",
            "ip_a": "192.168.50.75",
            "ip_b": "192.168.50.80",
            "created_at": "2026-03-15T14:00:00+00:00",
            "rules_installed": true
        }
    ],
    "total": 1
}
```

| Field | Description |
|-------|-------------|
| `ip_a` / `ip_b` | The IP addresses at which the OpenFlow rules are currently keyed. Updated automatically if a device's IP changes. `null` if the IP was not yet known when the permit was created. |
| `rules_installed` | Whether the four OpenFlow rules at priority 160 are currently active in OVS. `false` if one or both device IPs are unknown, or if the OVS switch is not connected. |

---

## `POST /policy/lateral-permits`

Grant bidirectional unicast IP communication between two IoT devices. Installs four OpenFlow rules at priority 160 that override the anti-lateral-movement drop at priority 150 for the specific permitted pair.

**Pre-requisites:**

Proxy ARP must be enabled on `br0` before devices can resolve each other's IP address. Without it the permit rules will be installed but ARP will fail and no communication will occur:

```bash
sudo sysctl -w net.ipv4.conf.br0.proxy_arp=1
sudo sysctl -w net.ipv4.conf.br0.proxy_arp_pvlan=1
```

Both devices must be known to the policy engine (i.e. they must appear in `GET /policy/devices`). If a device is listed but its `ip` field is `null`, the permit will be recorded but rules will not be installed until the device's IP is observed.

**curl**

```bash
curl -X POST http://127.0.0.1:8080/policy/lateral-permits \
  -H "Content-Type: application/json" \
  -d '{"mac_a": "aa:bb:cc:dd:ee:ff", "mac_b": "11:22:33:44:55:66"}'
```

**Request body**

```json
{
    "mac_a": "aa:bb:cc:dd:ee:ff",
    "mac_b": "11:22:33:44:55:66"
}
```

The order of `mac_a` and `mac_b` does not matter. A permit `{A, B}` is identical to `{B, A}`.

**Response (success, rules installed)**

```json
{
    "success": true,
    "permit": {
        "mac_a": "aa:bb:cc:dd:ee:ff",
        "mac_b": "11:22:33:44:55:66",
        "ip_a": "192.168.50.75",
        "ip_b": "192.168.50.80",
        "created_at": "2026-03-15T14:00:00+00:00",
        "rules_installed": true
    },
    "proxy_arp_enabled": true
}
```

**Response (success, rules pending - IP not yet known)**

```json
{
    "success": true,
    "permit": {
        "mac_a": "aa:bb:cc:dd:ee:ff",
        "mac_b": "11:22:33:44:55:66",
        "ip_a": null,
        "ip_b": "192.168.50.80",
        "created_at": "2026-03-15T14:00:00+00:00",
        "rules_installed": false
    },
    "proxy_arp_enabled": true
}
```

When `rules_installed` is `false`, the permit is stored and the rules will be installed automatically once traffic is observed from the device with the unknown IP.

**Error responses:**

| Status | Condition |
|--------|-----------|
| `400` | `mac_a` or `mac_b` missing from the request body |
| `400` | `mac_a` and `mac_b` are the same address |
| `400` | Either MAC is not a known device |
| `400` | A permit between this pair already exists |

---

## `DELETE /policy/lateral-permits`

Revoke a lateral movement permit. Removes the four OpenFlow rules at priority 160 immediately. Subsequent traffic between the pair is dropped by the anti-lateral-movement rule at priority 150.

The order of `mac_a` and `mac_b` does not matter.

**curl**

```bash
curl -X DELETE http://127.0.0.1:8080/policy/lateral-permits \
  -H "Content-Type: application/json" \
  -d '{"mac_a": "aa:bb:cc:dd:ee:ff", "mac_b": "11:22:33:44:55:66"}'
```

**Request body**

```json
{
    "mac_a": "aa:bb:cc:dd:ee:ff",
    "mac_b": "11:22:33:44:55:66"
}
```

**Response (success)**

```json
{
    "success": true,
    "mac_a": "aa:bb:cc:dd:ee:ff",
    "mac_b": "11:22:33:44:55:66"
}
```

**Error responses:** `400` if either MAC field is missing, or if no permit exists between the specified pair.
