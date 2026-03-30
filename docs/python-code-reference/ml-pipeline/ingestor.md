# ingestor.py

**Location:** `ml-pipeline/app/ingestor.py`

Tails the Zeek JSON log files (`conn.log`, `dns.log`, `dhcp.log`,
`http.log`, `ssl.log`) from the shared Docker volume. On each `poll()`
call it reads only the lines written since the last poll, tracking byte
offsets and file inodes to handle Zeek's hourly log rotation without
missing or duplicating entries.

For a functional description of the pipeline see
[Components: ML Pipeline](../../components/ml-pipeline/ml-pipeline.md).

---

## Code Reference

The following reference is auto-generated from the source code docstrings.

::: ingestor
