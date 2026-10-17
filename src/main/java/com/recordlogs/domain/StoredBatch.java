package com.recordlogs.domain;

import java.util.List;
import java.util.Objects;

/**
 * The OFF-chain data of one sealed batch: the raw logs and their leaf-hash index.
 * This is exactly the shape that gets persisted in Phase 4.
 *
 * <p><b>Why keep leaf hashes?</b> The chain stores only a 32-byte Merkle root, which is not enough
 * to tell WHICH log changed. The leaf hashes (32 bytes per log) are authenticated by the on-chain
 * root (re-hashing them must reproduce it), and once authenticated they let us pinpoint the exact
 * entry that was edited, deleted, added or moved.
 *
 * <p>Instances are immutable snapshots. No consistency is enforced between {@code logs} and
 * {@code leafHashes}: a tampered store is allowed to be inconsistent, and finding that out is the
 * job of {@link BatchedBlockchain#validate()}.
 *
 * @param logs       raw log entries, in order (may be empty/short if someone deleted entries)
 * @param leafHashes hex leaf hash of each originally sealed log, in order
 */
public record StoredBatch(List<String> logs, List<String> leafHashes) {

    public StoredBatch {
        Objects.requireNonNull(logs, "logs must not be null");
        Objects.requireNonNull(leafHashes, "leafHashes must not be null");
        logs = List.copyOf(logs);               // also rejects null elements
        leafHashes = List.copyOf(leafHashes);
        for (String h : leafHashes) {
            if (!Block.isValidHash(h)) {
                throw new IllegalArgumentException("leaf hash must be 64 lowercase hex chars");
            }
        }
    }
}
