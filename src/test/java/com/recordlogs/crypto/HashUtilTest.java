package com.recordlogs.crypto;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HashUtilTest {

    @Test
    void matchesKnownSha256TestVector() {
        // Standard NIST test vector for "abc"
        assertThat(HashUtil.sha256Hex("abc"))
                .isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    @Test
    void sameInputGivesSameHash() {
        assertThat(HashUtil.sha256Hex("hello")).isEqualTo(HashUtil.sha256Hex("hello"));
    }

    @Test
    void oneCharChangeCompletelyChangesHash() {
        assertThat(HashUtil.sha256Hex("hello")).isNotEqualTo(HashUtil.sha256Hex("hellp"));
    }

    @Test
    void outputIs64HexChars() {
        assertThat(HashUtil.sha256Hex("anything")).hasSize(64).matches("[0-9a-f]{64}");
    }

    @Test
    void rejectsNull() {
        assertThatThrownBy(() -> HashUtil.sha256Hex(null))
                .isInstanceOf(NullPointerException.class);
    }
}
