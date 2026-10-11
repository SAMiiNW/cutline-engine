# CUTLINE ENGINE

```text
TELEMETRY IN      two independent observation origins
FAULT MAP         complete node partition with citations
PATH SOLVER       every route from risk to protected services
CUTLINE           smallest deterministic edge set that blocks all routes
```

Incident response often begins with a list of unhealthy components and ends with a guessed isolation order. Cutline Engine turns the missing middle into an on-chain calculation.

The owner freezes a directed service graph, protected node indexes, and a separate responder. The responder anchors two telemetry sources. Validators classify every node as healthy, compromised, or unknown and bind every classification to source indexes and byte digests. Unknown nodes are treated as risk, not silently counted as safe.

The contract then enumerates every simple path from risk nodes to protected services and computes the smallest edge set that intersects all of them. No model proposes the cut. If a protected service is already compromised, the state is `BREACHED`. If no path reaches a protected service, it is `NO_EXPOSURE`. Otherwise the state is `CUT_READY` with exact edge indexes.

Any wallet may submit a fresh-origin execution receipt. Validators verify every required cut edge against that receipt while refetching the frozen telemetry. Complete execution becomes `CONTAINED`; any missing isolation becomes `CONTAINMENT_FAILED`.

## Instrument check

```bash
genvm-lint contracts/contract.py
python -m pytest -q
```

Included telemetry is synthetic. Separate hosts test source attribution and failure handling; they are not represented as independent operational authorities.

## StudioNet breaker log

- Contract: [`0x26677E077BF415fCe2F3700459f55BD63496B37b`](https://explorer-studio.genlayer.com/address/0x26677E077BF415fCe2F3700459f55BD63496B37b)
- Deployment: [`0x623df5...d043242`](https://explorer-studio.genlayer.com/tx/0x623df5b54e7adabb044b5557aaf309a742f5c8c5c73c08d494b0c9535d043242)
- Grid registration: [`0x803c30...cca21b`](https://explorer-studio.genlayer.com/tx/0x803c3052086a4d67cc6928be58c55ee4c9e1f5782ba2f1f265b522ea37cca21b)
- Telemetry inspection: [`0x7fe7a3...5bf259`](https://explorer-studio.genlayer.com/tx/0x7fe7a33d560cae0a1f847f7fa9cfa6f7fb29dfcf7b0cde8bc4192483475bf259)
- Containment receipt: [`0x9dcd0c...e77327`](https://explorer-studio.genlayer.com/tx/0x9dcd0c97e9108d2fce21d29ae3a709fb71cf7e6229e53cdd093664d6aae77327)
- Final record: `MESH-1791754701`, exposure paths `[[0,2],[1,3]]`, minimum cut `[0,1]`, state `CONTAINED`.
- Exact deployed source SHA-256: `4bba63d1f2faca10f4cc3a5b3aa3145a0116273eb8f2b26ff58c7b0a5c7342c0`.
