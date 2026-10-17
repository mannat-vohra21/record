package com.recordlogs.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Central place for all hashing in the project.
 * Keeping it here means we can swap the algorithm (e.g. SHA-3) in one spot.
 */
public final class HashUtil {

    private static final String ALGORITHM = "SHA-256";

    private HashUtil() {
        // utility class, no instances
    }

    /**
     * @return lowercase hex SHA-256 of the UTF-8 bytes of {@code input} (always 64 chars)
     */
    public static String sha256Hex(String input) {
        Objects.requireNonNull(input, "input must not be null");
        try {
            // MessageDigest is NOT thread-safe, so we create a fresh instance per call.
            MessageDigest digest = MessageDigest.getInstance(ALGORITHM);
            byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandatory in every JVM, so this can't realistically happen.
            throw new IllegalStateException(ALGORITHM + " not available", e);
        }
    }

    /**
     * @return the raw 32-byte SHA-256 digest of {@code input}. Used by the Merkle tree, which must
     *         hash raw bytes (prefix byte + child digests), not hex text.
     */
    public static byte[] sha256(byte[] input) {
        Objects.requireNonNull(input, "input must not be null");
        try {
            return MessageDigest.getInstance(ALGORITHM).digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(ALGORITHM + " not available", e);
        }
    }
}
