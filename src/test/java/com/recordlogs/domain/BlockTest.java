package com.recordlogs.domain;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BlockTest {

    private static final String PREV = Block.GENESIS_PREVIOUS_HASH;

    @Test
    void newBlockHasValidHash() {
        Block b = new Block(1, 1000L, PREV, "user admin failed login from 10.0.0.5");
        assertThat(b.hasValidHash()).isTrue();
        assertThat(b.getHash()).hasSize(64);
    }

    @Test
    void hashIsDeterministic() {
        Block a = new Block(1, 1000L, PREV, "log");
        Block b = new Block(1, 1000L, PREV, "log");
        assertThat(a.getHash()).isEqualTo(b.getHash());
    }

    @Test
    void changingAnyFieldChangesHash() {
        Block base = new Block(1, 1000L, PREV, "log");
        assertThat(new Block(2, 1000L, PREV, "log").getHash()).isNotEqualTo(base.getHash());
        assertThat(new Block(1, 1001L, PREV, "log").getHash()).isNotEqualTo(base.getHash());
        assertThat(new Block(1, 1000L, PREV, "log2").getHash()).isNotEqualTo(base.getHash());
    }

    @Test
    void restoredBlockWithAlteredDataFailsHashCheck() {
        Block original = new Block(1, 1000L, PREV, "file deleted by root");
        Block forged = Block.restore(1, 1000L, PREV, "nothing happened", original.getHash());
        assertThat(forged.hasValidHash()).isFalse();
    }

    @Test
    void restoredBlockWithOriginalContentAndHashPassesHashCheck() {
        Block original = new Block(1, 1000L, PREV, "file deleted by root");
        Block loaded = Block.restore(1, 1000L, PREV, "file deleted by root", original.getHash());
        assertThat(loaded.hasValidHash()).isTrue();
        assertThat(loaded.getHash()).isEqualTo(original.getHash());
    }

    @Test
    void restoreRejectsMalformedStoredHash() {
        // null, empty, too short, too long, uppercase hex, non-hex characters
        assertThatThrownBy(() -> Block.restore(1, 1000L, PREV, "x", null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Block.restore(1, 1000L, PREV, "x", ""))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Block.restore(1, 1000L, PREV, "x", "abc123"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Block.restore(1, 1000L, PREV, "x", "a".repeat(65)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Block.restore(1, 1000L, PREV, "x", "A".repeat(64)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Block.restore(1, 1000L, PREV, "x", "g".repeat(64)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsInvalidInput() {
        assertThatThrownBy(() -> new Block(-1, 1000L, PREV, "x"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Block(1, 1000L, "short", "x"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Block(1, 1000L, PREV, "  "))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Block(1, 1000L, null, "x"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
