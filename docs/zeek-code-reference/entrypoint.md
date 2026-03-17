# entrypoint.sh

**Location:** `zeek/entrypoint.sh`

Container startup script mounted into the Zeek Docker container. Polls for
the `zeek-eth1` mirror interface to appear in the container's network
namespace, logging a warning every 60 seconds while waiting. Once the
interface is up it hands control to Zeek via `exec`. Keeping the container
alive while waiting prevents the restart loop that would otherwise create a
new network namespace and invalidate any veth pair already attached by the
host-side `attach-zeek-mirror.sh` service.

See [Services: Zeek Mirror](../services/zeek-mirror.md) for the full
attach sequence.

---

```bash
--8<-- "zeek/entrypoint.sh"
```
