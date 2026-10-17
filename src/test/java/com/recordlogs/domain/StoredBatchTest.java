package com.recordlogs.domain;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class StoredBatchTest {

    private static final String HASH = "cd".repeat(32);

    @Test
    void copiesItsListsDefensively() {
        List<String> logs = new ArrayList<>(List.of("a", "b"));
        List<String> hashes = new ArrayList<>(List.of(HASH, HASH));
        StoredBatch batch = new StoredBatch(logs, hashes);

        logs.add("c");
        hashes.clear();

        assertThat(batch.logs()).hasSize(2);
        assertThat(batch.leafHashes()).hasSize(2);
        assertThatThrownBy(() -> batch.logs().add("x")).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void rejectsNullsAndMalformedLeafHashes() {
        assertThatThrownBy(() -> new StoredBatch(null, List.of())).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new StoredBatch(List.of(), null)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new StoredBatch(List.of("a"), List.of("short")))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
