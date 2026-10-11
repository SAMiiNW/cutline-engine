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
