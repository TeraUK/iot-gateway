# log-maintenance.sh

**Location:** `scripts/log-maintenance.sh`

Compresses Zeek's rotated log files, enforces the 90-day archive retention
policy, reports Zeek log volume disk usage, and verifies AdGuard Home and
dnsmasq logging health. Installed by `install.sh` as a daily cron job at
03:00 and can be run manually at any time.

```bash
sudo /usr/local/bin/log-maintenance.sh
```

See [Operations: Log Maintenance](../operations/log-maintenance.md) for
the full operational context.

---

```bash
--8<-- "scripts/log-maintenance.sh"
```
