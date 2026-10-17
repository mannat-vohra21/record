package com.recordlogs.domain;

/**
 * A trusted snapshot of the chain head, used to detect TAIL TRUNCATION.
 *
 * <p><b>Why a chain alone cannot detect tail deletion:</b> every block commits only to its
 * predecessor (via {@code previousHash}); nothing commits to the blocks that come AFTER it.
 * If an attacker deletes the last N blocks, what remains is a perfectly valid, merely shorter
 * chain, so {@link Blockchain#validate()} still passes. The only thing that "remembers" how
 * long the chain used to be is the head hash, and that has to be remembered somewhere the
 * attacker cannot also edit.
 *
 * <p><b>Why the anchor must be stored separately:</b> if the anchor lived in the same table
 * (or the same trust domain) as the blocks, an attacker who can delete blocks could simply
 * delete or rewrite the anchor too. In Phase 4 anchors are persisted in their own table;
 * for stronger guarantees they should also be exported somewhere append-only or external
 * (a different DB user with insert-only rights, WORM storage, a signed e-mail, a public timestamp, ...).
 * An anchor is only as trustworthy as the place it is kept.
 *
 * @param height     position of the head block when the anchor was taken (genesis = 0),
 *                   so a chain must contain at least {@code height + 1} blocks to satisfy it
 * @param latestHash hash of the head block at that moment
 * @param timestamp  epoch millis when the anchor was created (informational, not used in validation)
 */
public record ChainAnchor(long height, String latestHash, long timestamp) {

    public ChainAnchor {
        if (height < 0) {
            throw new IllegalArgumentException("height must be >= 0");
        }
        if (!Block.isValidHash(latestHash)) {
            throw new IllegalArgumentException("latestHash must be 64 lowercase hex chars");
        }
        if (timestamp < 0) {
            throw new IllegalArgumentException("timestamp must be >= 0");
        }
    }
}
