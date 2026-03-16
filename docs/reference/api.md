# REST API Reference

The Ryu policy application exposes a REST API on port `8080`. All endpoints return JSON. The API is used by the Zeek detection scripts, the ML pipeline, the `dns_cache_updater` service, and can be used manually for device management.

Base URL: `http://127.0.0.1:8080` (host) or `http://ryu:8080` (from containers on `gateway-net`)

---

## `GET /policy/status`

Returns the current state of the policy engine.

**Response**

```json
{
  "switch_connected": true,
  "switch_dpid": 1,
  "wifi_port": 1,
  "wifi_interface": "wlp3s0",
  "rules_installed": true,
  "rule_count": 18,
  "known_devices": 4,
  "isolated_devices": 1,
  "connect_time": "2026-03-15T10:00:00+00:00",
  "gateway_ip": "192.168.50.1",
  "iot_subnet": "192.168.50.0/255.255.255.0",
  "enforcement_mode": "enforcing",
  "profiled_devices": 3,
  "dns_cache_entries": 47,
  "denied_log_size": 12
}
```

---

## `GET /policy/devices`

Returns all MAC addresses seen on the WiFi port, with profile and isolation status.

**Response**

```json
{
  "devices": {
    "aa:bb:cc:dd:ee:ff": {
      "first_seen": "2026-03-10T08:00:00+00:00",
      "last_seen": "2026-03-15T12:30:00+00:00",
      "has_profile": true,
      "profile_name": "Smart Thermostat",
      "is_isolated": false
    }
  },
  "total": 4
}
```

---

## `POST /policy/isolate`

Quarantine a device by MAC address. Installs a priority-65535 DROP rule for all traffic to and from that MAC.

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

Remove isolation from a device. Deletes the priority-65535 DROP rules. The device returns to its normal policy (allowlist enforcement or general WAN access).

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

**Request body:** none required

**Response**

```json
{
  "success": true,
  "profiles_loaded": 3
}
```

---

## `POST /policy/allowlists/mode`

Switch the enforcement mode between `learning` and `enforcing`.

**Request body**

```json
{
  "mode": "enforcing"
}
```

Valid values: `"learning"` or `"enforcing"`

---

## `POST /policy/dns-cache`

Update the in-memory DNS cache with domain-to-IP mappings. Used by the `dns_cache_updater` service.

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

---

## `GET /policy/denied-log`

Returns recent denied connection attempts from profiled devices in enforcing mode. Useful for identifying destinations to add to allowlists.

**Response**

```json
{
  "entries": [
    {
      "ts": "2026-03-15T12:30:00+00:00",
      "mac": "aa:bb:cc:dd:ee:ff",
      "dst_ip": "203.0.113.99",
      "dst_port": 443,
      "reason": "destination not in allowlist"
    }
  ],
  "total": 1
}
```
