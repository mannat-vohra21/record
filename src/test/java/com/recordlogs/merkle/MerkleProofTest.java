package com.recordlogs.merkle;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MerkleProofTest {

    private static final int[] SIZES = {1, 2, 3, 4, 5, 7, 8, 1000};

    private static List<String> logs(String prefix, int n) {
        List<String> list = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            list.add(prefix + i);
        }
        return list;
    }

    private static int ceilLog2(int n) {
        return n <= 1 ? 0 : 32 - Integer.numberOfLeadingZeros(n - 1);
    }

    /** Flips the first hex digit so the value stays well-formed but is wrong. */
    private static String corrupt(String hex) {
        char first = hex.charAt(0) == '0' ? '1' : '0';
        return first + hex.substring(1);
    }

    // ------------------------------------------------------------ happy path

    @Test
    void proofVerifiesForEveryLeaf() {
        for (int n : SIZES) {
            List<String> data = logs("log ", n);
            MerkleTree tree = MerkleTree.of(data);
            for (int i = 0; i < n; i++) {
                MerkleProof proof = tree.generateProof(i);
                assertThat(proof.leafIndex()).isEqualTo(i);
                assertThat(MerkleProof.verify(data.get(i), proof, tree.getRoot()))
                        .as("n=" + n + ", leaf=" + i)
                        .isTrue();
            }
        }
    }

    @Test
    void proofSizeIsLogarithmic() {
        for (int n : SIZES) {
            MerkleTree tree = MerkleTree.of(logs("log ", n));
            int bound = ceilLog2(n);
            for (int i = 0; i < n; i++) {
                assertThat(tree.generateProof(i).size())
                        .as("n=" + n + ", leaf=" + i)
                        .isLessThanOrEqualTo(bound);
            }
        }
        // concrete anchors: 1 leaf -> empty proof, 8 leaves -> 3 hashes, 1000 leaves -> at most 10
        assertThat(MerkleTree.of(logs("x", 1)).generateProof(0).size()).isEqualTo(0);
        assertThat(MerkleTree.of(logs("x", 8)).generateProof(5).size()).isEqualTo(3);
        assertThat(MerkleTree.of(logs("x", 1000)).generateProof(999).size()).isLessThanOrEqualTo(10);
    }

    @Test
    void promotedNodesSkipLevelsInTheirProof() {
        // 3 leaves: leaf 2 is promoted past level 0, so only N(a,b) is needed, on the LEFT
        MerkleProof p3 = MerkleTree.of(logs("l", 3)).generateProof(2);
        assertThat(p3.size()).isEqualTo(1);
        assertThat(p3.sides().get(0)).isEqualTo(MerkleProof.Side.LEFT);

        // 5 leaves: leaf 4 is promoted through two levels, one sibling (the 4-leaf subtree) on the LEFT
        MerkleProof p5 = MerkleTree.of(logs("l", 5)).generateProof(4);
        assertThat(p5.size()).isEqualTo(1);
        assertThat(p5.sides().get(0)).isEqualTo(MerkleProof.Side.LEFT);
    }

    @Test
    void convenienceAccessorsMatchTheSiblings() {
        MerkleProof proof = MerkleTree.of(logs("l", 8)).generateProof(2);
        assertThat(proof.siblingHashes()).hasSize(proof.size());
        assertThat(proof.sides()).hasSize(proof.size());
        for (int i = 0; i < proof.size(); i++) {
            assertThat(proof.siblingHashes().get(i)).isEqualTo(proof.siblings().get(i).hash());
            assertThat(proof.sides().get(i)).isEqualTo(proof.siblings().get(i).side());
        }
    }

    // ------------------------------------------------------------ failures

    @Test
    void proofFailsForTamperedLeaf() {
        for (int n : SIZES) {
            List<String> data = logs("log ", n);
            MerkleTree tree = MerkleTree.of(data);
            for (int i = 0; i < n; i += Math.max(1, n / 20)) {
                MerkleProof proof = tree.generateProof(i);
                assertThat(MerkleProof.verify(data.get(i) + "!", proof, tree.getRoot()))
                        .as("n=" + n + ", leaf=" + i)
                        .isFalse();
            }
        }
    }

    @Test
    void proofFailsForWrongRoot() {
        List<String> data = logs("log ", 9);
        MerkleTree tree = MerkleTree.of(data);
        MerkleProof proof = tree.generateProof(3);

        assertThat(MerkleProof.verify(data.get(3), proof, corrupt(tree.getRoot()))).isFalse();
        assertThat(MerkleProof.verify(data.get(3), proof, MerkleTree.of(logs("other ", 9)).getRoot())).isFalse();
    }

    @Test
    void proofFailsForWrongSiblingOrder() {
        List<String> data = logs("log ", 8);
        MerkleTree tree = MerkleTree.of(data);
        MerkleProof proof = tree.generateProof(2);
        assertThat(proof.size()).isEqualTo(3);

        // same hashes, reversed order
        List<MerkleProof.Sibling> reversed = new ArrayList<>(proof.siblings());
        Collections.reverse(reversed);
        assertThat(MerkleProof.verify(data.get(2), new MerkleProof(2, reversed), tree.getRoot())).isFalse();

        // same hashes and order, but every side flipped
        List<MerkleProof.Sibling> flipped = new ArrayList<>();
        for (MerkleProof.Sibling s : proof.siblings()) {
            flipped.add(new MerkleProof.Sibling(s.hash(), s.side() == MerkleProof.Side.LEFT
                    ? MerkleProof.Side.RIGHT : MerkleProof.Side.LEFT));
        }
        assertThat(MerkleProof.verify(data.get(2), new MerkleProof(2, flipped), tree.getRoot())).isFalse();
    }

    @Test
    void proofFailsForTamperedSiblingOrTruncatedProof() {
        List<String> data = logs("log ", 8);
        MerkleTree tree = MerkleTree.of(data);
        MerkleProof proof = tree.generateProof(5);

        List<MerkleProof.Sibling> altered = new ArrayList<>(proof.siblings());
        MerkleProof.Sibling first = altered.get(0);
        altered.set(0, new MerkleProof.Sibling(corrupt(first.hash()), first.side()));
        assertThat(MerkleProof.verify(data.get(5), new MerkleProof(5, altered), tree.getRoot())).isFalse();

        List<MerkleProof.Sibling> shortened = new ArrayList<>(proof.siblings());
        shortened.remove(shortened.size() - 1);
        assertThat(MerkleProof.verify(data.get(5), new MerkleProof(5, shortened), tree.getRoot())).isFalse();
    }

    @Test
    void proofFromADifferentBatchFails() {
        // Batch A and batch B both contain "shared" at index 0, but differ elsewhere.
        List<String> batchA = List.of("shared", "a1", "a2", "a3");
        List<String> batchB = List.of("shared", "b1", "b2", "b3");
        MerkleTree treeA = MerkleTree.of(batchA);
        MerkleTree treeB = MerkleTree.of(batchB);

        MerkleProof proofA = treeA.generateProof(0);
        MerkleProof proofB = treeB.generateProof(0);

        assertThat(MerkleProof.verify("shared", proofA, treeA.getRoot())).isTrue();
        assertThat(MerkleProof.verify("shared", proofB, treeB.getRoot())).isTrue();
        // swapped: right data, right-looking proof, wrong batch
        assertThat(MerkleProof.verify("shared", proofA, treeB.getRoot())).isFalse();
        assertThat(MerkleProof.verify("shared", proofB, treeA.getRoot())).isFalse();
    }

    @Test
    void proofForAnotherLeafDoesNotVerifyThisLeaf() {
        List<String> data = logs("log ", 8);
        MerkleTree tree = MerkleTree.of(data);
        assertThat(MerkleProof.verify(data.get(2), tree.generateProof(3), tree.getRoot())).isFalse();
        assertThat(MerkleProof.verify(data.get(3), tree.generateProof(2), tree.getRoot())).isFalse();
    }

    @Test
    void verifyReturnsFalseInsteadOfThrowingOnGarbage() {
        MerkleTree tree = MerkleTree.of(logs("log ", 4));
        MerkleProof proof = tree.generateProof(0);

        assertThat(MerkleProof.verify(null, proof, tree.getRoot())).isFalse();
        assertThat(MerkleProof.verify("log 0", null, tree.getRoot())).isFalse();
        assertThat(MerkleProof.verify("log 0", proof, null)).isFalse();
        assertThat(MerkleProof.verify("log 0", proof, "not-a-hash")).isFalse();
        assertThat(MerkleProof.verify("log 0", proof, tree.getRoot().toUpperCase())).isFalse();
    }

    // ------------------------------------------------------------ API contract

    @Test
    void generateProofRejectsOutOfRangeIndex() {
        MerkleTree tree = MerkleTree.of(logs("log ", 5));
        assertThatThrownBy(() -> tree.generateProof(-1)).isInstanceOf(IndexOutOfBoundsException.class);
        assertThatThrownBy(() -> tree.generateProof(5)).isInstanceOf(IndexOutOfBoundsException.class);
    }

    @Test
    void proofRecordsRejectMalformedValues() {
        assertThatThrownBy(() -> new MerkleProof.Sibling("short", MerkleProof.Side.LEFT))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new MerkleProof.Sibling("A".repeat(64), MerkleProof.Side.LEFT))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new MerkleProof.Sibling("a".repeat(64), null))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new MerkleProof(-1, List.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new MerkleProof(0, null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void proofSiblingListIsImmutable() {
        MerkleProof proof = MerkleTree.of(logs("log ", 4)).generateProof(1);
        assertThatThrownBy(() -> proof.siblings().clear())
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
