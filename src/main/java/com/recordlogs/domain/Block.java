package com.recordlogs.domain;

import com.recordlogs.crypto.HashUtil;

import java.util.regex.Pattern;

/**
 * An immutable block.
 *
 * <p>{@code data} holds the raw log line in the naive chain, and the Merkle root
 * of a batch of logs in the optimized chain (Phase 2).
 */
public final class Block {

    /** previousHash of the genesis block: 64 zeros. */
    public static final String GENESIS_PREVIOUS_HASH = "0".repeat(64);

    private static final Pattern HEX_64 = Pattern.compile("^[0-9a-f]{64}$");

    private final long index;
    private final long timestamp;      // epoch millis (UTC), easy to store and compare
    private final String previousHash;
    private final String data;
    private final String hash;

    /** Creates a NEW block: the hash is computed from the fields. */
    public Block(long index, long timestamp, String previousHash, String data) {
        validateFields(index, timestamp, previousHash, data);
        this.index = index;
        this.timestamp = timestamp;
        this.previousHash = previousHash;
        this.data = data;
        this.hash = computeHash();
    }

    /** Private: used by restore(), keeps the supplied hash as-is (after format validation). */
    private Block(long index, long timestamp, String previousHash, String data, String hash) {
        validateFields(index, timestamp, previousHash, data);
        if (!isValidHash(hash)) {
            throw new IllegalArgumentException("storedHash must be 64 lowercase hex chars");
        }
        this.index = index;
        this.timestamp = timestamp;
        this.previousHash = previousHash;
        this.data = data;
        this.hash = hash;
    }

    /**
     * Rebuilds a block from storage WITHOUT recomputing its hash.
     * If someone altered the data in the DB, the stored hash will no longer match,
     * and {@link #hasValidHash()} will expose it. Used by persistence and tests.
     *
     * <p>The stored hash is only checked for FORMAT (64 lowercase hex chars), never for
     * correctness: correctness is exactly what {@link #hasValidHash()} and
     * {@link Blockchain#validate()} are for.
     *
     * @throws IllegalArgumentException if any field is invalid or {@code storedHash} is malformed
     */
    public static Block restore(long index, long timestamp, String previousHash,
                                String data, String storedHash) {
        return new Block(index, timestamp, previousHash, data, storedHash);
    }

    /** SHA-256 over index|timestamp|previousHash|data. */
    public String computeHash() {
        return HashUtil.sha256Hex(index + "|" + timestamp + "|" + previousHash + "|" + data);
    }

    /** True if the stored hash matches the block's current content. */
    public boolean hasValidHash() {
        return hash.equals(computeHash());
    }

    /** True if {@code value} is exactly 64 lowercase hex characters (the format of a SHA-256 hex digest). */
    static boolean isValidHash(String value) {
        return value != null && HEX_64.matcher(value).matches();
    }

    private static void validateFields(long index, long timestamp, String previousHash, String data) {
        if (index < 0) {
            throw new IllegalArgumentException("index must be >= 0");
        }
        if (timestamp < 0) {
            throw new IllegalArgumentException("timestamp must be >= 0");
        }
        if (!isValidHash(previousHash)) {
            throw new IllegalArgumentException("previousHash must be 64 lowercase hex chars");
        }
        if (data == null || data.isBlank()) {
            throw new IllegalArgumentException("data must not be blank");
        }
    }

    public long getIndex() { return index; }
    public long getTimestamp() { return timestamp; }
    public String getPreviousHash() { return previousHash; }
    public String getData() { return data; }
    public String getHash() { return hash; }

    @Override
    public String toString() {
        return "Block{index=" + index + ", ts=" + timestamp
                + ", hash=" + hash.substring(0, 8) + "..., prev=" + previousHash.substring(0, 8) + "...}";
    }
}
