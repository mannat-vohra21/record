package com.recordlogs.domain;

import java.util.List;
import java.util.Objects;

/**
 * Outcome of validating a {@link BatchedBlockchain}. A plain {@link ValidationResult} only knows
 * block positions; here we also need the batch and the exact log entries involved, so this is a
 * separate type (it wraps the underlying chain result when the chain itself is broken).
 *
 * @param valid        true if everything checks out
 * @param reason       null when valid
 * @param batchIndex   0-based batch (= block position - 1), or -1 when not applicable
 * @param entryIndexes 0-based log positions within the batch that changed (empty if not applicable)
 * @param chainResult  the underlying chain failure when {@code reason == CHAIN_INVALID}, else null
 * @param message      human-readable description
 */
public record BatchValidationResult(boolean valid, Reason reason, int batchIndex,
                                    List<Integer> entryIndexes, ValidationResult chainResult,
                                    String message) {

    public enum Reason {
        CHAIN_INVALID,          // the underlying block chain failed (see chainResult)
        MALFORMED_BLOCK_DATA,   // a batch block's data is not a valid batch header
        ROOT_MISMATCH,          // stored Merkle data and the on-chain root disagree (root or index tampered)
        LOG_EDITED,             // same number of logs, some content changed
        LOG_DELETED,            // fewer logs than sealed
        LOG_ADDED,              // more logs than sealed
        LOGS_REORDERED,         // same logs, different order
        BATCH_DATA_MISSING,     // a block exists but its raw batch data is gone
        BATCH_DATA_ORPHAN       // raw batch data exists with no block (e.g. blocks were deleted)
    }

    public BatchValidationResult {
        entryIndexes = List.copyOf(Objects.requireNonNull(entryIndexes, "entryIndexes must not be null"));
    }

    public static BatchValidationResult ok() {
        return new BatchValidationResult(true, null, -1, List.of(), null, "Batched chain is valid");
    }

    /** Wraps a failed underlying chain validation; batch = failed block position - 1. */
    public static BatchValidationResult chainFailure(ValidationResult chain) {
        return new BatchValidationResult(false, Reason.CHAIN_INVALID,
                Math.max(-1, chain.failedPosition() - 1), List.of(), chain, chain.message());
    }

    public static BatchValidationResult batchFailure(Reason reason, int batchIndex, String message) {
        return new BatchValidationResult(false, reason, batchIndex, List.of(), null, message);
    }

    public static BatchValidationResult entryFailure(Reason reason, int batchIndex,
                                                     List<Integer> entryIndexes, String message) {
        return new BatchValidationResult(false, reason, batchIndex, entryIndexes, null, message);
    }
}
