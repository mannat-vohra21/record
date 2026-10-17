# Record

Tamper-evident security log system built on an optimized blockchain data structure.

> Brand name: **Record**. Maven artifact: `record-logs`. Java base package: `com.recordlogs`
> (the main class is `RecordApplication`; no Java class or package segment is called `record`,
> to avoid clashing with `java.lang.Record` and the `record` contextual keyword).

## Status

**Phase 1: core blockchain (done).** `Block` (SHA-256), `Blockchain`, `ChainAnchor` (tail-truncation
detection), `ValidationResult`.

**Phase 2: Merkle tree, Merkle proofs, batched chain (done).** No database and no REST API yet.

| Package | What it contains |
|---|---|
| `crypto` | `HashUtil`: SHA-256 (hex for strings, raw bytes for the Merkle tree) |
| `domain` | `Block`, `Blockchain`, `ChainAnchor`, `ValidationResult` (Phase 1); `BatchedBlockchain`, `BatchHeader`, `StoredBatch`, `BatchValidationResult` (Phase 2) |
| `merkle` | `MerkleTree`, `MerkleProof` |
| `benchmark` | `MiniComparison`: console comparison of naive vs batched chain |

### How Phase 2 works

- Logs are buffered. When the buffer reaches the batch size (or `flush()` is called) the batch becomes
  **one block** whose data is just `MERKLE|<root>|<count>`.
- The raw logs and a leaf-hash index (32 bytes per log) stay **off-chain**, in memory for now
  (persistence comes in Phase 4).
- `MerkleTree`: leaf hash `SHA-256(0x00 || data)`, internal hash `SHA-256(0x01 || left || right)`
  (domain separation stops second-preimage attacks). An odd node is **promoted unchanged**, never
  duplicated (Bitcoin's duplication makes `[a,b,c]` and `[a,b,c,c]` share a root, CVE-2012-2459).
- `MerkleProof`: `ceil(log2 n)` sibling hashes at most; `MerkleProof.verify(leaf, proof, root)`.
- `BatchedBlockchain.verifyLog(batch, log)` checks one log with a Merkle proof against the on-chain root.
- `BatchedBlockchain.validate()` checks the chain, then recomputes every batch's root from its stored
  logs. On a mismatch it reports the exact batch and entries (`LOG_EDITED`, `LOG_DELETED`, `LOG_ADDED`,
  `LOGS_REORDERED`) using the leaf-hash index, which is first authenticated against the on-chain root.

## Run the tests

Requires JDK 17+ and Maven.

    mvn clean test

Expected final lines (the mini comparison table is printed in the middle of the output):

    Tests run: 99, Failures: 0, Errors: 0, Skipped: 0
    BUILD SUCCESS

Only the comparison:

    mvn -Dtest=MiniComparisonTest test

(or run `MiniComparison.main` from your IDE; optional arguments: log count and batch size).

## Mini comparison: naive chain vs batched chain

10,000 generated security logs, batch size 100 (fixed random seed, so the sizes are reproducible;
"bytes" = UTF-8 size of each block as `index|timestamp|previousHash|data|hash`, plus raw logs and
leaf-hash index for the batched chain):

| | Naive (1 block per log) | Batched (Merkle root only) |
|---|---|---|
| Blocks | 10,001 | 101 |
| On-chain bytes | 2,218,116 | 22,345 |
| Off-chain raw logs | (inside the blocks) | 729,069 |
| Off-chain leaf-hash index | none | 640,000 |
| **Total bytes** | **2,218,116** | **1,391,414** |

- **On-chain footprint: 99.0% smaller** (10,001 blocks down to 101).
- **Total storage: 37.3% smaller.** The raw logs have to be kept in both designs; the saving comes from
  not repeating the per-block overhead (index, timestamp, previous hash, hash) for every log.
  Phase 6 (compression and pruning) targets the raw logs and the leaf-hash index.
- The leaf-hash index is what makes it possible to say *which* log changed (a bare root cannot). It is
  stored here as 64 hex characters per log; as raw bytes it would be half that size.

Full benchmarking (search time, verification time, graphs) is Phase 7.

## Threat model

**Detected**

| Attack | Detected by | Result |
|---|---|---|
| Edit a block's data (hash left as is) | `Blockchain.validate()` | `HASH_MISMATCH` at that block |
| Edit a block and recompute its hash | `Blockchain.validate()` | `LINK_BROKEN` at the next block |
| Delete a block in the middle | `Blockchain.validate()` | `INDEX_MISMATCH` |
| Reorder blocks | `Blockchain.validate()` | `INDEX_MISMATCH` |
| Timestamp going backwards | `Blockchain.validate()` | `TIMESTAMP_REGRESSION` |
| Malformed genesis block | `Blockchain.validate()` | `INVALID_GENESIS` |
| Delete the last N blocks / cut and re-extend | `validate(anchor)` only | `TRUNCATED` |
| Edit a stored log | `BatchedBlockchain.validate()` | `LOG_EDITED`, exact batch and entry |
| Delete a stored log | `BatchedBlockchain.validate()` | `LOG_DELETED`, exact batch and entry |
| Insert a stored log | `BatchedBlockchain.validate()` | `LOG_ADDED`, exact batch and entry |
| Reorder stored logs | `BatchedBlockchain.validate()` | `LOGS_REORDERED`, exact batch and entries |
| Change a root on-chain (block hash not fixed) | `BatchedBlockchain.validate()` | `CHAIN_INVALID` (`HASH_MISMATCH`) |
| Change a root and fix the block hash, not the last block | `BatchedBlockchain.validate()` | `CHAIN_INVALID` (`LINK_BROKEN`) |
| Change the root of the LAST block and fix its hash | `BatchedBlockchain.validate()` | `ROOT_MISMATCH` (the plain chain alone is fooled) |
| Edit a log and also its leaf-hash index | `BatchedBlockchain.validate()` | `ROOT_MISMATCH` (detected, entry not located) |
| Alter only the leaf-hash index | `BatchedBlockchain.validate()` | `ROOT_MISMATCH` |
| Delete a batch's raw data, or delete blocks but keep raw data | `BatchedBlockchain.validate()` | `BATCH_DATA_MISSING` / `BATCH_DATA_ORPHAN` |
| Second-preimage forgery (internal node passed off as a leaf) | `MerkleTree` domain separation | proof does not verify |
| Extending the leaf list by repeating the last entry (CVE-2012-2459) | `MerkleTree` odd-node promotion | different root |

A plain `validate()` cannot detect tail truncation: every block commits only to its predecessor, so a
shorter chain is still a valid chain. A `ChainAnchor` must be kept separately from the blocks.

**Not covered yet**

- Logs still in the buffer are not on the chain, so they are not tamper-evident (and are lost on a crash)
  until the batch is sealed. Smaller batches shrink this window, larger ones save more space.
- Anchors are not persisted anywhere yet (separate table planned for Phase 4); until then truncation is
  only detectable if the caller keeps the anchor.
- If an attacker can also modify or delete the anchor, truncation and full-chain rewrites go undetected.
  The anchor store needs its own protection (separate DB user, append-only or external storage).
- If an attacker edits a log AND its leaf hash, the tampering is detected but the exact entry cannot be
  located (the stored hashes no longer reproduce the root).
- A plain chain validation misses an edit of the LAST block with a recomputed hash; use the batched
  validation or an anchor.
- Entries inside a batch are not individually timestamped or signed: a forged batch appended at the end is
  valid, and authenticity of the writer is not proven.
- Timestamps come from the system clock and are not independently trusted.
- No persistence, no search index, no forensic timeline, no pruning yet (later phases).
