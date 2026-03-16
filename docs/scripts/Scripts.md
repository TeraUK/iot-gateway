# Scripts Reference

This section documents every runnable script in the repository. Each entry covers what the script does, how to invoke it, what each section of its output means, and what to do when something fails.

All scripts in `scripts/` must be run from the repository root. Scripts that interact with OVS, systemd, or Docker must be run as root (`sudo`).

Related but not covered here are the two custom daemons [Services](profile-builder.md)

---

## Quick navigation

- Building device profiles [profile_builder.py](profile-builder.md).
- Verifying gateway health [health-check.sh](health-check.md).
- Log maintenance [log-maintenance.sh](log-maintenance.md).
- Per-phase implementation verification [verify-phase[n].sh](verification-scripts.md).

---


