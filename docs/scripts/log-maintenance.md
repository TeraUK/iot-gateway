## log-maintenance.sh

**Purpose:** Compresses Zeek's rotated log files, enforces the 90-day archive retention policy, reports disk usage, and verifies AdGuard and dnsmasq logging health. This script runs automatically as a daily cron job at 03:00, installed by `install.sh`. It can also be run manually at any time.

```bash
sudo /usr/local/bin/log-maintenance.sh
```

Full documentation for this script, including how it interacts with the ML pipeline during log rotation, is in [Log Maintenance](../operations/log-maintenance.md).

---

## Interpreting PASS / FAIL / WARN

All verification scripts and the health check use the same three-level output convention:

`[PASS]` means the check succeeded and that component is working as expected.

`[FAIL]` means a critical check failed. The script will exit with code `1` and the system should not be considered operational for the phase or component in question. Read the output line immediately below the `[FAIL]` for the specific value that was found and the expected value.

`[WARN]` means something is in a non-ideal state but the system can still function. Common examples include fail mode being set to `standalone` instead of `secure` (correct during development), or the log maintenance cron not yet being installed. Warnings should be addressed before moving to production but do not indicate an immediate fault.

The summary block at the end of each script reports a count of each level and exits with `1` if there are any failures, making the scripts straightforward to use in automated checks or CI pipelines:

```bash
sudo ./scripts/health-check.sh && echo "Gateway healthy" || echo "Failures detected"
```