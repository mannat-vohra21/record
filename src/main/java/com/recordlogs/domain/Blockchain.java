package com.recordlogs.domain;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * In-memory chain of blocks. In the baseline (naive) setup every log entry is one block.
 * Mutating methods are synchronized so concurrent log writers can't fork the chain.
 *
 * <p><b>Creating vs. loading:</b> {@code new Blockchain()} must only be used for a brand-new
 * chain. Persisted chains must always be loaded via {@link #fromBlocks(List)}.
 */
public class Blockchain {

    private static final Logger log = LoggerFactory.getLogger(Blockchain.class);

    private final List<Block> blocks = new ArrayList<>();

    /**
     * Creates a brand-new chain containing only a freshly generated genesis block.
     *
     * <p><b>Use this ONLY for a brand-new chain.</b> The genesis block gets the current time,
     * so every call produces a different genesis hash. Calling {@code new Blockchain()} on
     * application restart would silently create a different, unrelated chain instead of
     * continuing the stored one. Persisted chains must be loaded via {@link #fromBlocks(List)}.
     */
    public Blockchain() {
        blocks.add(new Block(0, System.currentTimeMillis(),
                Block.GENESIS_PREVIOUS_HASH, "GENESIS"));
    }

    private Blockchain(List<Block> restored) {
        blocks.addAll(restored);
    }

    /**
     * Rebuilds a chain from stored blocks (e.g. from PostgreSQL). This is the correct way to
     * load any persisted chain.
     * Deliberately does NOT validate: call {@link #validate()} to find out if it was tampered with.
     */
    public static Blockchain fromBlocks(List<Block> stored) {
        if (stored == null || stored.isEmpty()) {
            throw new IllegalArgumentException("a chain needs at least the genesis block");
        }
        return new Blockchain(stored);
    }

    /** Appends a new block linked to the current latest block. */
    public synchronized Block addBlock(String data) {
        Block last = blocks.get(blocks.size() - 1);
        // Never let the timestamp go backwards, even if the system clock does.
        long ts = Math.max(System.currentTimeMillis(), last.getTimestamp());
        Block block = new Block(last.getIndex() + 1, ts, last.getHash(), data);
        blocks.add(block);
        log.debug("Added {}", block);
        return block;
    }

    /**
     * Snapshots the current head as a {@link ChainAnchor}. Take it while the chain is known to be
     * good and store it SEPARATELY from the blocks (see {@link ChainAnchor} for why).
     */
    public synchronized ChainAnchor createAnchor() {
        Block head = blocks.get(blocks.size() - 1);
        return new ChainAnchor(blocks.size() - 1, head.getHash(), System.currentTimeMillis());
    }

    /**
     * Walks the whole chain and reports the FIRST problem found, if any. O(n).
     *
     * <p><b>Cannot detect tail truncation</b> (deleting the last N blocks): use
     * {@link #validate(ChainAnchor)} for that.
     */
    public synchronized ValidationResult validate() {
        for (int i = 0; i < blocks.size(); i++) {
            Block current = blocks.get(i);

            // 1. The block's own hash must match its content.
            if (!current.hasValidHash()) {
                return ValidationResult.invalid(i, ValidationResult.Reason.HASH_MISMATCH,
                        "Block " + current.getIndex() + " content does not match its stored hash");
            }

            if (i == 0) {
                if (current.getIndex() != 0
                        || !Block.GENESIS_PREVIOUS_HASH.equals(current.getPreviousHash())) {
                    return ValidationResult.invalid(0, ValidationResult.Reason.INVALID_GENESIS,
                            "Genesis block is malformed");
                }
                continue;
            }

            Block previous = blocks.get(i - 1);

            // 2. Indexes must be consecutive: catches deleted or reordered blocks.
            if (current.getIndex() != previous.getIndex() + 1) {
                return ValidationResult.invalid(i, ValidationResult.Reason.INDEX_MISMATCH,
                        "Expected index " + (previous.getIndex() + 1) + " but found " + current.getIndex());
            }

            // 3. The link: this block must point at the previous block's real hash.
            if (!current.getPreviousHash().equals(previous.getHash())) {
                return ValidationResult.invalid(i, ValidationResult.Reason.LINK_BROKEN,
                        "Block " + current.getIndex() + " does not link to block " + previous.getIndex());
            }

            // 4. Time must not go backwards.
            if (current.getTimestamp() < previous.getTimestamp()) {
                return ValidationResult.invalid(i, ValidationResult.Reason.TIMESTAMP_REGRESSION,
                        "Block " + current.getIndex() + " is older than its predecessor");
            }
        }
        return ValidationResult.ok();
    }

    /**
     * Everything {@link #validate()} does, plus a check against a trusted {@link ChainAnchor}.
     * Fails with {@link ValidationResult.Reason#TRUNCATED} if
     * <ul>
     *   <li>the chain is shorter than the anchor requires (tail blocks were deleted), or</li>
     *   <li>the block at the anchor's height has a different hash (the chain was rewritten
     *       or cut and re-extended).</li>
     * </ul>
     * A chain LONGER than the anchor is fine: blocks legitimately appended after the anchor
     * was taken do not invalidate it.
     *
     * <p>Internal tampering is reported first (same result as {@link #validate()}); the anchor
     * check only runs on an internally consistent chain. For a too-short chain,
     * {@code failedPosition} is the first missing position (= the chain's size); for a hash
     * divergence it is the anchor's height.
     *
     * @param trusted an anchor stored outside the blocks' own trust domain
     */
    public synchronized ValidationResult validate(ChainAnchor trusted) {
        Objects.requireNonNull(trusted, "trusted anchor must not be null");

        ValidationResult base = validate();
        if (!base.valid()) {
            return base;
        }

        // The chain passed validate(), so positions == indexes here.
        if (blocks.size() <= trusted.height()) {
            return ValidationResult.invalid(blocks.size(), ValidationResult.Reason.TRUNCATED,
                    "Chain has " + blocks.size() + " blocks but the anchor requires at least "
                            + (trusted.height() + 1) + ": tail blocks were deleted");
        }

        Block atAnchor = blocks.get((int) trusted.height());
        if (!atAnchor.getHash().equals(trusted.latestHash())) {
            return ValidationResult.invalid((int) trusted.height(), ValidationResult.Reason.TRUNCATED,
                    "Block at height " + trusted.height()
                            + " differs from the anchored hash: chain was truncated or rewritten");
        }

        return ValidationResult.ok();
    }

    public synchronized Block getLatest() { return blocks.get(blocks.size() - 1); }

    public synchronized Block getBlock(int position) { return blocks.get(position); }

    public synchronized int size() { return blocks.size(); }

    /** Read-only snapshot, so callers can't modify the chain behind our back. */
    public synchronized List<Block> getBlocks() {
        return Collections.unmodifiableList(new ArrayList<>(blocks));
    }
}
