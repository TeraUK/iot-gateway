# build-docs.sh

**Location:** `installation/build-docs.sh`

Creates an isolated Python virtual environment, installs the MkDocs
toolchain from `docs/requirements.txt`, and builds the documentation site
to `./site/`. Reuses the existing virtual environment on subsequent runs
unless `--clean` is passed. Pass `--serve` to start a local development
server at `http://127.0.0.1:8000` after building.

```bash
./installation/build-docs.sh
./installation/build-docs.sh --clean   # Rebuild venv from scratch
./installation/build-docs.sh --serve   # Build and serve locally
```

---

```bash
--8<-- "installation/build-docs.sh"
```
