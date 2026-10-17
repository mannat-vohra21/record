package com.recordlogs.domain;

import java.util.Optional;

/**
 * The compact payload stored in a block's {@code data} field by {@link BatchedBlockchain}:
 * the Merkle root of the batch and how many logs it covers.
 *
 * <p>Wire format (strict, canonical): {@code MERKLE|<64 lowercase hex root>|<count>}
 *
 * @param merkleRoot 64 lowercase hex chars
 * @param logCount   number of logs in the batch (>= 1), no leading zeros in the string form
 */
public record BatchHeader(String merkleRoot, int logCount) {

    static final String TAG = "MERKLE";

    public BatchHeader {
        if (!Block.isValidHash(merkleRoot)) {
            throw new IllegalArgumentException("merkleRoot must be 64 lowercase hex chars");
        }
        if (logCount < 1) {
            throw new IllegalArgumentException("logCount must be >= 1");
        }
    }

    /** The string stored in {@link Block#getData()}. */
    public String toData() {
        return TAG + "|" + merkleRoot + "|" + logCount;
    }

    /**
     * Parses block data written by {@link #toData()}. Never throws: block data may have been
     * tampered with, so a malformed string simply yields an empty Optional.
     */
    public static Optional<BatchHeader> tryParse(String data) {
        if (data == null) {
            return Optional.empty();
        }
        String[] parts = data.split("\\|", -1);
        if (parts.length != 3 || !TAG.equals(parts[0]) || !Block.isValidHash(parts[1])) {
            return Optional.empty();
        }
        try {
            int count = Integer.parseInt(parts[2]);
            // canonical form only: rejects "+5", "05", "-1", "0"
            if (count < 1 || !Integer.toString(count).equals(parts[2])) {
                return Optional.empty();
            }
            return Optional.of(new BatchHeader(parts[1], count));
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }
}
