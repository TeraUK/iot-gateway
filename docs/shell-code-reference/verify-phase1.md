# verify-phase1.sh

**Location:** `scripts/verify-phase1.sh`

Verifies Phase 1 deployment: DNS filtering, DNSSEC, nftables interception
rules, DoT/DoQ blocking, Zeek logging, hostapd, dnsmasq, and the log
maintenance cron job. Run at the end of Phase 1 setup and any time DNS
filtering behaviour seems incorrect.

```bash
sudo ./scripts/verify-phase1.sh
```

See [Scripts: Verification Scripts](../scripts/verification-scripts.md)
for a description of all checks and common failure fixes.

---

```bash
--8<-- "scripts/verify-phase1.sh"
```
