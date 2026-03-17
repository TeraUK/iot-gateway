# health-check.sh

**Location:** `scripts/health-check.sh`

Comprehensive system health check covering all gateway components: OVS
bridge, Ryu controller, nftables, AdGuard Home, dnsmasq, hostapd, Zeek,
the Zeek mirror service, and the ML pipeline. Exits with code `0` if all
critical checks pass, `1` if any `FAIL` items are present. Run manually at
any time or use it in automated monitoring.

```bash
sudo ./scripts/health-check.sh
```

See [Scripts: Health Check](../scripts/health-check.md) for a full
description of the output format and common failure fixes.

---

```bash
--8<-- "scripts/health-check.sh"
```
