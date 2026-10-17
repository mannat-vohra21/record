package com.recordlogs.merkle;

import com.recordlogs.crypto.HashUtil;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Immutable binary Merkle tree over a batch of log entries.
 *
 * <h2>Domain separation (second-preimage protection)</h2>
 * <pre>
 *   leaf hash     = SHA-256( 0x00 || data )
 *   internal hash = SHA-256( 0x01 || left || right )      (left, right = raw 32-byte digests)
 * </pre>
 * Without the prefixes, a leaf and an internal node are hashed the same way, so an attacker can
 * present the 64 bytes {@code left || right} of an internal node as if it were a "log entry": that
 * fake leaf hashes to the very same value as the internal node, giving a valid but SHORTER proof for
 * data that was never logged (the second-preimage attack on Merkle trees). With distinct prefixes a
 * leaf hash can never equal an internal-node hash for the same bytes, so internal nodes cannot be
 * passed off as leaves. Because {@code left} and {@code right} are always exactly 32 bytes, the
 * concatenation is also unambiguous.
 *
 * <h2>Odd number of nodes: promote, never duplicate</h2>
 * When a level has an odd number of nodes, the last node is carried up to the next level UNCHANGED.
 * Bitcoin instead pairs it with a copy of itself, which makes {@code [a,b,c]} and {@code [a,b,c,c]}
 * produce the SAME root (CVE-2012-2459: two different transaction lists, one hash). Promotion keeps
 * those roots different, so the leaf list cannot be silently extended with a repeated last entry.
 * The price is that a promoted node has no sibling at that level, so its proof is slightly shorter.
 */
public final class MerkleTree {

    static final byte LEAF_PREFIX = 0x00;
    static final byte NODE_PREFIX = 0x01;

    private static final HexFormat HEX = HexFormat.of();
    private static final Pattern DIGEST_HEX = Pattern.compile("^[0-9a-f]{64}$");

    /** levels.get(0) = leaf hashes, last level = single root. Raw bytes are never exposed. */
    private final List<List<byte[]>> levels;

    private MerkleTree(List<byte[]> leafHashes) {
        List<List<byte[]>> built = new ArrayList<>();
        List<byte[]> level = leafHashes;
        built.add(level);
        while (level.size() > 1) {
            List<byte[]> next = new ArrayList<>((level.size() + 1) / 2);
            for (int i = 0; i < level.size(); i += 2) {
                if (i + 1 < level.size()) {
                    next.add(hashNode(level.get(i), level.get(i + 1)));
                } else {
                    next.add(level.get(i));   // odd node: promoted unchanged
                }
            }
            built.add(next);
            level = next;
        }
        this.levels = built;
    }

    /**
     * Builds the tree over the given log entries (UTF-8 encoded).
     *
     * @throws NullPointerException     if the list or any entry is null
     * @throws IllegalArgumentException if the list is empty
     */
    public static MerkleTree of(List<String> logs) {
        Objects.requireNonNull(logs, "logs must not be null");
        if (logs.isEmpty()) {
            throw new IllegalArgumentException("a Merkle tree needs at least one leaf");
        }
        List<byte[]> leaves = new ArrayList<>(logs.size());
        for (String log : logs) {
            Objects.requireNonNull(log, "log entries must not be null");
            leaves.add(hashLeaf(log.getBytes(StandardCharsets.UTF_8)));
        }
        return new MerkleTree(leaves);
    }

    /**
     * Builds the tree from already-computed leaf hashes (hex), e.g. the stored leaf-hash index of a
     * batch whose raw logs are no longer needed or are being checked against it.
     *
     * @throws IllegalArgumentException if empty or any hash is not 64 lowercase hex chars
     */
    public static MerkleTree fromLeafHashes(List<String> leafHashesHex) {
        Objects.requireNonNull(leafHashesHex, "leafHashes must not be null");
        if (leafHashesHex.isEmpty()) {
            throw new IllegalArgumentException("a Merkle tree needs at least one leaf");
        }
        List<byte[]> leaves = new ArrayList<>(leafHashesHex.size());
        for (String h : leafHashesHex) {
            if (!isValidDigestHex(h)) {
                throw new IllegalArgumentException("leaf hash must be 64 lowercase hex chars");
            }
            leaves.add(HEX.parseHex(h));
        }
        return new MerkleTree(leaves);
    }

    /** Hex leaf hash of one log entry: SHA-256(0x00 || UTF-8 data). */
    public static String leafHash(String data) {
        Objects.requireNonNull(data, "data must not be null");
        return HEX.formatHex(hashLeaf(data.getBytes(StandardCharsets.UTF_8)));
    }

    /** Merkle root as 64 lowercase hex chars. */
    public String getRoot() {
        List<byte[]> top = levels.get(levels.size() - 1);
        return HEX.formatHex(top.get(0));
    }

    public int getLeafCount() {
        return levels.get(0).size();
    }

    /** Immutable list of the hex leaf hashes, in log order. */
    public List<String> getLeafHashes() {
        return levels.get(0).stream().map(HEX::formatHex).toList();
    }

    /**
     * Builds the inclusion proof for one leaf. O(log n) size.
     *
     * @throws IndexOutOfBoundsException if {@code index} is outside {@code [0, leafCount)}
     */
    public MerkleProof generateProof(int index) {
        int leafCount = getLeafCount();
        if (index < 0 || index >= leafCount) {
            throw new IndexOutOfBoundsException(
                    "leaf index " + index + " out of range [0, " + leafCount + ")");
        }
        List<MerkleProof.Sibling> siblings = new ArrayList<>();
        int position = index;
        for (int lvl = 0; lvl < levels.size() - 1; lvl++) {
            List<byte[]> nodes = levels.get(lvl);
            int siblingPosition = position ^ 1;               // neighbour in the same pair
            if (siblingPosition < nodes.size()) {
                MerkleProof.Side side = (position & 1) == 0
                        ? MerkleProof.Side.RIGHT              // we are the left child
                        : MerkleProof.Side.LEFT;              // we are the right child
                siblings.add(new MerkleProof.Sibling(HEX.formatHex(nodes.get(siblingPosition)), side));
            }
            // else: this node was promoted at this level, so there is nothing to add
            position >>= 1;
        }
        return new MerkleProof(index, siblings);
    }

    // ------------------------------------------------------------------ hashing

    /** SHA-256(0x00 || data). */
    static byte[] hashLeaf(byte[] data) {
        byte[] input = new byte[1 + data.length];
        input[0] = LEAF_PREFIX;
        System.arraycopy(data, 0, input, 1, data.length);
        return HashUtil.sha256(input);
    }

    /** SHA-256(0x01 || left || right). */
    static byte[] hashNode(byte[] left, byte[] right) {
        byte[] input = new byte[1 + left.length + right.length];
        input[0] = NODE_PREFIX;
        System.arraycopy(left, 0, input, 1, left.length);
        System.arraycopy(right, 0, input, 1 + left.length, right.length);
        return HashUtil.sha256(input);
    }

    static boolean isValidDigestHex(String value) {
        return value != null && DIGEST_HEX.matcher(value).matches();
    }
}
