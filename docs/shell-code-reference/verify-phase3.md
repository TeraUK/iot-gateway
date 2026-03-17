# verify-phase3.sh

**Location:** `scripts/verify-phase3.sh`

Verifies Phase 3 deployment: per-device destination allowlist
infrastructure, enforcement mode, device profile loading, the DNS cache
updater service, and the Ryu allowlist and DNS cache endpoints. Run after
deploying device profiles and again when switching to enforcing mode.

```bash
sudo ./scripts/verify-phase3.sh
```

See [Scripts: Verification Scripts](../scripts/verification-scripts.md)
for a description of all checks and common failure fixes.

---

```bash
--8<-- "scripts/verify-phase3.sh"
```
