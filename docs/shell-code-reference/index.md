# Shell Code Reference

This section embeds the full source of every shell script in the repository
directly from the source files. The content is included at build time via
MkDocs' snippet system, so the pages always reflect the current version on
disk.

For operational documentation covering what each script does and how to use
it, see the [Scripts](../scripts/Scripts.md) and
[Services](../services/services-overview.md) sections.

---

## Scripts in this section

| Script | Location | Purpose |
|--------|----------|---------|
| [install.sh](install.md) | `installation/` | Full gateway environment setup |
| [build-docs.sh](build-docs.md) | `installation/` | Build the MkDocs documentation site |
| [health-check.sh](health-check.md) | `scripts/` | Verify all gateway components |
| [log-maintenance.sh](log-maintenance.md) | `scripts/` | Compress Zeek logs and enforce retention |
| [verify-phase1.sh](verify-phase1.md) | `scripts/` | Verify Phase 1 (DNS filtering) |
| [verify-phase2.sh](verify-phase2.md) | `scripts/` | Verify Phase 2 (micro-segmentation) |
| [verify-phase3.sh](verify-phase3.md) | `scripts/` | Verify Phase 3 (per-device allowlists) |
| [verify-phase4.sh](verify-phase4.md) | `scripts/` | Verify Phase 4 (detection and isolation) |
| [attach-zeek-mirror.sh](attach-zeek-mirror.md) | `Services/zeek-mirror/` | Attach OVS mirror to Zeek container |
