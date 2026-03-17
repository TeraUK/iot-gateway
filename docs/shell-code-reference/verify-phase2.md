# verify-phase2.sh

**Location:** `scripts/verify-phase2.sh`

Verifies Phase 2 deployment: OVS bridge configuration, Ryu container
status, the policy REST API, micro-segmentation rules, essential service
rules (DHCP, DNS, NTP, ARP), and the default deny rule. Run after Ryu
first connects to OVS and after any change to the gateway policy.

```bash
sudo ./scripts/verify-phase2.sh
```

See [Scripts: Verification Scripts](../scripts/verification-scripts.md)
for a description of all checks and common failure fixes.

---

```bash
--8<-- "scripts/verify-phase2.sh"
```
