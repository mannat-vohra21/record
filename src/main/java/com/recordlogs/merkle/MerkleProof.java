package com.recordlogs.merkle;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/**
 * An inclusion proof ("audit path") for one leaf of a {@link MerkleTree}.
 *
 * <p>It holds the sibling hash at every level where the leaf's ancestor HAS a sibling, together
 * with the side the sibling sits on. A verifier needs only the leaf, this proof and the trusted
 * root: it re-hashes upwards and compares. The proof has at most {@code ceil(log2 n)} entries, so
 * checking one log among a million needs ~20 hashes instead of re-reading all the logs.
 *
 * <p>Levels where the ancestor was promoted (odd node, see {@link MerkleTree}) contribute no entry.
 *
 * @param leafIndex position of the leaf in the batch (informational: verification does not trust it,
 *                  it relies only on the sibling hashes and sides)
 * @param siblings  sibling hashes from the leaf level up to just below the root
 */
public record MerkleProof(int leafIndex, List<Sibling> siblings) {

    /** Side of the sibling relative to the node being proven. */
    public enum Side { LEFT, RIGHT }

    /**
     * One step of the audit path.
     *
     * @param hash lowercase hex SHA-256 digest of the sibling node (exactly 64 chars, i.e. 32 bytes)
     * @param side where the sibling sits: LEFT means hash(0x01 || sibling || current)
     */
    public record Sibling(String hash, Side side) {
        public Sibling {
            if (!MerkleTree.isValidDigestHex(hash)) {
                throw new IllegalArgumentException("sibling hash must be 64 lowercase hex chars");
            }
            Objects.requireNonNull(side, "side must not be null");
        }
    }

    public MerkleProof {
        if (leafIndex < 0) {
            throw new IllegalArgumentException("leafIndex must be >= 0");
        }
        siblings = List.copyOf(Objects.requireNonNull(siblings, "siblings must not be null"));
    }

    /** Number of hashes in the proof (O(log n)). */
    public int size() {
        return siblings.size();
    }

    /** Convenience view: just the sibling hashes, bottom to top. */
    public List<String> siblingHashes() {
        return siblings.stream().map(Sibling::hash).toList();
    }

    /** Convenience view: just the sides, bottom to top. */
    public List<Side> sides() {
        return siblings.stream().map(Sibling::side).toList();
    }

    /**
     * Recomputes the root from {@code leafData} and {@code proof} and compares it to
     * {@code expectedRoot}.
     *
     * <p>Never throws on bad input: a null argument or a malformed root simply yields {@code false},
     * because proofs usually come from an untrusted party.
     *
     * @param leafData     the log entry exactly as it was originally stored
     * @param proof        the audit path for that entry
     * @param expectedRoot the trusted root (e.g. the one stored on-chain), 64 lowercase hex chars
     * @return true only if the leaf is proven to be part of the tree with that root
     */
    public static boolean verify(String leafData, MerkleProof proof, String expectedRoot) {
        if (leafData == null || proof == null || !MerkleTree.isValidDigestHex(expectedRoot)) {
            return false;
        }
        HexFormat hex = HexFormat.of();
        byte[] current = MerkleTree.hashLeaf(leafData.getBytes(StandardCharsets.UTF_8));
        for (Sibling step : proof.siblings()) {
            byte[] sibling = hex.parseHex(step.hash());   // validated as 64 hex chars => 32 bytes
            current = (step.side() == Side.LEFT)
                    ? MerkleTree.hashNode(sibling, current)
                    : MerkleTree.hashNode(current, sibling);
        }
        return MessageDigest.isEqual(current, hex.parseHex(expectedRoot));
    }
}
