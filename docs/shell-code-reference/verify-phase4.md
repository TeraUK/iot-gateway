# verify-phase4.sh

**Location:** `scripts/verify-phase4.sh`

Verifies Phase 4 deployment: Zeek detection scripts, IOC files, the
`iot_alerts.log` output, Ryu isolation and release endpoints, the OVS
mirror port, and Zeek-to-Ryu network connectivity. Run after loading the
detection scripts and before enabling `auto_isolate`.

```bash
sudo ./scripts/verify-phase4.sh
```

See [Scripts: Verification Scripts](../scripts/verification-scripts.md)
for a description of all checks and common failure fixes.

---

```bash
--8<-- "scripts/verify-phase4.sh"
```
