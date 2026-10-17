# Record

Tamper-evident security log system built on an optimized blockchain data structure.

> Brand name: **Record**. Maven artifact: `record-logs`. Java base package: `com.recordlogs`
> (the main class is `RecordApplication`; no Java class or package segment is called `record`,
> to avoid clashing with `java.lang.Record` and the `record` contextual keyword).

## Phase 1 status

Core blockchain, no database and no Merkle tree yet:

- `Block`: immutable block, SHA-256 hash over `index|timestamp|previousHash|data`, hardened `restore()` for loading stored blocks
- `Blockchain`: append, `validate()`, and `validate(ChainAnchor)` for tail-truncation detection
- `ChainAnchor`: trusted snapshot of the chain head (height, latest hash, timestamp)
- `ValidationResult`: exact failed position and reason (`HASH_MISMATCH`, `LINK_BROKEN`, `INDEX_MISMATCH`, `TIMESTAMP_REGRESSION`, `INVALID_GENESIS`, `TRUNCATED`)
- 34 unit tests

## Run the tests

Requires JDK 17+ and Maven.

    mvn clean test

Expected final lines:

    Tests run: 34, Failures: 0, Errors: 0, Skipped: 0
    BUILD SUCCESS

## Threat model (Phase 1)

**Detected**

| Attack | Detected by | Reason |
|---|---|---|
| Edit a block's data (hash left as is) | `validate()` | `HASH_MISMATCH` at that block |
| Edit a block and recompute its hash | `validate()` | `LINK_BROKEN` at the next block |
| Delete a block in the middle | `validate()` | `INDEX_MISMATCH` |
| Reorder blocks | `validate()` | `INDEX_MISMATCH` |
| Timestamp going backwards | `validate()` | `TIMESTAMP_REGRESSION` |
| Malformed genesis block | `validate()` | `INVALID_GENESIS` |
| Delete the last N blocks (tail truncation) | `validate(anchor)` only | `TRUNCATED` |
| Cut the tail and append different blocks | `validate(anchor)` only | `TRUNCATED` |

A plain `validate()` cannot detect tail truncation: every block commits only to its predecessor,
so a shorter chain is still a valid chain. A `ChainAnchor` must be kept separately from the blocks.

**Not covered yet**

- Anchors are not persisted anywhere yet (separate table planned for Phase 4); until then truncation is only detectable if the caller keeps the anchor.
- If an attacker can also modify or delete the anchor, truncation and full-chain rewrites go undetected. The anchor store needs its own protection (separate DB user, append-only or external storage).
- Editing only the LAST block and recomputing its hash is invisible to `validate()` (no later block points at it); it is caught only against an anchor.
- Forged blocks appended at the end are valid: there are no signatures, so authenticity of the writer is not proven.
- Timestamps come from the system clock and are not independently trusted.
- No persistence, no Merkle batching or proofs, no search index, no forensic timeline yet (later phases).
