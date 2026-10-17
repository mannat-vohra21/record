package com.recordlogs.domain;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ChainAnchorTest {

    private static final String HASH = "a".repeat(64);

    @Test
    void keepsItsValues() {
        ChainAnchor anchor = new ChainAnchor(5, HASH, 1234L);
        assertThat(anchor.height()).isEqualTo(5);
        assertThat(anchor.latestHash()).isEqualTo(HASH);
        assertThat(anchor.timestamp()).isEqualTo(1234L);
    }

    @Test
    void rejectsInvalidFields() {
        assertThatThrownBy(() -> new ChainAnchor(-1, HASH, 1L))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ChainAnchor(0, "short", 1L))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ChainAnchor(0, null, 1L))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ChainAnchor(0, HASH, -1L))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
