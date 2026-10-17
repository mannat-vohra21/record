package com.recordlogs.domain;

/**
 * Outcome of validating a chain. For an invalid chain it tells exactly
 * WHERE (position in the chain) and WHY, which Phase 5 uses for forensics.
 */
public record ValidationResult(boolean valid, int failedPosition, Reason reason, String message) {

    public enum Reason {
        HASH_MISMATCH,          // block content changed but hash not updated
        LINK_BROKEN,            // previousHash doesn't match prior block's hash
        INDEX_MISMATCH,         // block missing/reordered/duplicated
        TIMESTAMP_REGRESSION,   // block is older than its predecessor
        INVALID_GENESIS,        // genesis block has wrong index or previousHash
        TRUNCATED               // chain is shorter than, or diverges from, a trusted ChainAnchor
    }

    public static ValidationResult ok() {
        return new ValidationResult(true, -1, null, "Chain is valid");
    }

    public static ValidationResult invalid(int position, Reason reason, String message) {
        return new ValidationResult(false, position, reason, message);
    }
}
