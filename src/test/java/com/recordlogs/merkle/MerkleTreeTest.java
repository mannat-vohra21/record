package com.recordlogs.merkle;

import com.recordlogs.crypto.HashUtil;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MerkleTreeTest {

    private static final int[] SIZES = {1, 2, 3, 4, 5, 7, 8, 1000};
    private static final HexFormat HEX = HexFormat.of();

    private static List<String> logs(int n) {
        List<String> list = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            list.add("log entry " + i);
        }
        return list;
    }

    private static byte[] leaf(String data) {
        return MerkleTree.hashLeaf(data.getBytes(StandardCharsets.UTF_8));
    }

    private static String hex(byte[] bytes) {
        return HEX.formatHex(bytes);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    // ------------------------------------------------------------ basics

    @Test
    void rootIsDeterministicAndWellFormed() {
        String root = MerkleTree.of(logs(5)).getRoot();
        assertThat(root).isEqualTo(MerkleTree.of(logs(5)).getRoot());
        assertThat(root).hasSize(64).matches("[0-9a-f]{64}");
    }

    @Test
    void singleLeafRootIsTheLeafHash() {
        MerkleTree tree = MerkleTree.of(List.of("only"));
        assertThat(tree.getRoot()).isEqualTo(hex(leaf("only")));
        assertThat(tree.getLeafCount()).isEqualTo(1);
    }

    @Test
    void rootChangesWhenAnySingleLeafChanges() {
        for (int n : SIZES) {
            String base = MerkleTree.of(logs(n)).getRoot();
            for (int i = 0; i < n; i++) {
                List<String> modified = logs(n);
                modified.set(i, "TAMPERED");
                assertThat(MerkleTree.of(modified).getRoot())
                        .as("n=" + n + ", changed leaf=" + i)
                        .isNotEqualTo(base);
            }
        }
    }

    @Test
    void rootDependsOnLeafOrder() {
        assertThat(MerkleTree.of(List.of("a", "b", "c")).getRoot())
                .isNotEqualTo(MerkleTree.of(List.of("b", "a", "c")).getRoot());
    }

    @Test
    void rejectsEmptyAndNullInput() {
        assertThatThrownBy(() -> MerkleTree.of(List.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> MerkleTree.of(null))
                .isInstanceOf(NullPointerException.class);
        List<String> withNull = new ArrayList<>();
        withNull.add("a");
        withNull.add(null);
        assertThatThrownBy(() -> MerkleTree.of(withNull))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void exposesLeafCountAndImmutableLeafHashes() {
        MerkleTree tree = MerkleTree.of(logs(6));
        assertThat(tree.getLeafCount()).isEqualTo(6);
        assertThat(tree.getLeafHashes()).hasSize(6);
        assertThat(tree.getLeafHashes().get(2)).isEqualTo(MerkleTree.leafHash("log entry 2"));
        assertThatThrownBy(() -> tree.getLeafHashes().add("x"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    // ------------------------------------------- odd nodes: promote, never duplicate

    @Test
    void oddNodeIsPromotedUnchangedNotDuplicated() {
        byte[] a = leaf("a"), b = leaf("b"), c = leaf("c"), d = leaf("d"), e = leaf("e"),
                f = leaf("f"), g = leaf("g");

        // 3 leaves: N(N(a,b), c)  -- c is promoted as is
        byte[] n3 = MerkleTree.hashNode(MerkleTree.hashNode(a, b), c);
        assertThat(MerkleTree.of(List.of("a", "b", "c")).getRoot()).isEqualTo(hex(n3));
        // ... and it is NOT Bitcoin's N(N(a,b), N(c,c))
        byte[] bitcoinStyle = MerkleTree.hashNode(MerkleTree.hashNode(a, b), MerkleTree.hashNode(c, c));
        assertThat(MerkleTree.of(List.of("a", "b", "c")).getRoot()).isNotEqualTo(hex(bitcoinStyle));

        // 5 leaves: N(N(N(a,b), N(c,d)), e)
        byte[] n5 = MerkleTree.hashNode(
                MerkleTree.hashNode(MerkleTree.hashNode(a, b), MerkleTree.hashNode(c, d)), e);
        assertThat(MerkleTree.of(List.of("a", "b", "c", "d", "e")).getRoot()).isEqualTo(hex(n5));

        // 7 leaves: N(N(N(a,b),N(c,d)), N(N(e,f), g))
        byte[] n7 = MerkleTree.hashNode(
                MerkleTree.hashNode(MerkleTree.hashNode(a, b), MerkleTree.hashNode(c, d)),
                MerkleTree.hashNode(MerkleTree.hashNode(e, f), g));
        assertThat(MerkleTree.of(List.of("a", "b", "c", "d", "e", "f", "g")).getRoot()).isEqualTo(hex(n7));
    }

    @Test
    void repeatingTheLastLeafChangesTheRoot() {
        // CVE-2012-2459: with duplication, [a,b,c] and [a,b,c,c] share a root. Here they must not.
        assertThat(MerkleTree.of(List.of("a", "b", "c")).getRoot())
                .isNotEqualTo(MerkleTree.of(List.of("a", "b", "c", "c")).getRoot());
        assertThat(MerkleTree.of(logs(5)).getRoot()).isNotEqualTo(rootWithRepeatedLast(5));
        assertThat(MerkleTree.of(logs(7)).getRoot()).isNotEqualTo(rootWithRepeatedLast(7));
    }

    private static String rootWithRepeatedLast(int n) {
        List<String> list = logs(n);
        list.add(list.get(n - 1));
        return MerkleTree.of(list).getRoot();
    }

    @Test
    void prefixesOfTheSameListAllHaveDistinctRoots() {
        Set<String> roots = new HashSet<>();
        for (int n = 1; n <= 12; n++) {
            roots.add(MerkleTree.of(logs(n)).getRoot());
        }
        assertThat(roots).hasSize(12);
    }

    // ------------------------------------------------- domain separation

    @Test
    void leafAndNodeHashingAreDomainSeparated() {
        byte[] left = leaf("left");
        byte[] right = leaf("right");
        byte[] bytes = concat(left, right);

        // same bytes, different prefix => different digest
        assertThat(hex(MerkleTree.hashLeaf(bytes))).isNotEqualTo(hex(MerkleTree.hashNode(left, right)));
        // a leaf hash is not plain SHA-256 of the data
        assertThat(hex(leaf("abc"))).isNotEqualTo(HashUtil.sha256Hex("abc"));
    }

    @Test
    void internalNodeCannotBePassedOffAsLeaf() {
        MerkleTree tree = MerkleTree.of(List.of("a", "b", "c", "d"));
        byte[] la = leaf("a"), lb = leaf("b"), lc = leaf("c"), ld = leaf("d");
        byte[] n12 = MerkleTree.hashNode(la, lb);
        byte[] n34 = MerkleTree.hashNode(lc, ld);
        // sanity: this is really the tree layout
        assertThat(tree.getRoot()).isEqualTo(hex(MerkleTree.hashNode(n12, n34)));

        // (1) the 64 bytes that hash to the internal node, offered as a "leaf", do not hash to it
        byte[] preimage = concat(la, lb);
        assertThat(hex(MerkleTree.hashLeaf(preimage))).isNotEqualTo(hex(n12));

        // (2) forged SHORT proof: claim the left half is a single leaf, sibling = n34 on the right
        MerkleProof forged = new MerkleProof(0,
                List.of(new MerkleProof.Sibling(hex(n34), MerkleProof.Side.RIGHT)));
        String[] fakeLeaves = {
                hex(n12),                                                    // the node itself
                hex(la) + hex(lb),                                           // its preimage as hex text
                new String(preimage, StandardCharsets.ISO_8859_1)            // its preimage as raw bytes
        };
        for (String fake : fakeLeaves) {
            assertThat(MerkleProof.verify(fake, forged, tree.getRoot())).isFalse();
        }

        // (3) a 2-leaf tree built over the internal node hashes has a different root
        assertThat(MerkleTree.of(List.of(hex(n12), hex(n34))).getRoot()).isNotEqualTo(tree.getRoot());
    }

    // ------------------------------------------------- leaf-hash based construction

    @Test
    void fromLeafHashesReproducesTheSameTree() {
        for (int n : SIZES) {
            MerkleTree original = MerkleTree.of(logs(n));
            MerkleTree rebuilt = MerkleTree.fromLeafHashes(original.getLeafHashes());
            assertThat(rebuilt.getRoot()).as("n=" + n).isEqualTo(original.getRoot());
        }
    }

    @Test
    void fromLeafHashesRejectsBadInput() {
        assertThatThrownBy(() -> MerkleTree.fromLeafHashes(List.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> MerkleTree.fromLeafHashes(List.of("abc")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> MerkleTree.fromLeafHashes(List.of("A".repeat(64))))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
