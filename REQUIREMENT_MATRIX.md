# Requirement matrix

| Requirement | Code path | Targeted proof | Status |
|---|---|---|---|
| Unique grid and separated responder | `register_grid` | duplicate and unauthorized tests | PASS |
| Complete node classification | `_classify` | forged partition validator test | PASS |
| Attributed telemetry and digests | `_fetch`, `_classify` | lifecycle readback | PASS |
| Deterministic path and minimum-cut derivation | `enumerate_paths`, `minimum_cut` | branch and parallel-path tests | PASS |
| Unknown fails safe as risk | `inspect_telemetry` | unknown-node cut test | PASS |
| Receipt covers every cut edge | `_verify_cut`, `confirm_cut` | incomplete execution test | PASS |
| Exact reviewed deployment | deployment receipt and fetched source | `evidence/deployment-verification.json` | PASS |
| Finalized containment lifecycle | Explorer transactions and readback | `evidence/live-proof.json` | PASS |
