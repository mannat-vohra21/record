package com.recordlogs.crypto;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HashUtilBytesTest {

    @Test
    void byteOverloadMatchesNistVectorAndHexVariant() {
        byte[] digest = HashUtil.sha256("abc".getBytes(StandardCharsets.UTF_8));
        assertThat(digest.length).isEqualTo(32);
        assertThat(HexFormat.of().formatHex(digest))
                .isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .isEqualTo(HashUtil.sha256Hex("abc"));
    }

    @Test
    void byteOverloadRejectsNull() {
        assertThatThrownBy(() -> HashUtil.sha256((byte[]) null))
                .isInstanceOf(NullPointerException.class);
    }
}
