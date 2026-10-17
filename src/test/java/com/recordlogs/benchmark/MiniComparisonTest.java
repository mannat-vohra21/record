package com.recordlogs.benchmark;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class MiniComparisonTest {

    @Test
    void batchedChainUsesFarFewerBlocksAndBytes() {
        MiniComparison.Result r = MiniComparison.compare(10_000, 100);
        MiniComparison.print(r, System.out);          // the numbers you put in the README

        assertThat(r.naiveBlocks()).isEqualTo(10_001);     // genesis + one block per log
        assertThat(r.batchedBlocks()).isEqualTo(101);      // genesis + 100 batches of 100
        assertThat(r.batchedOnChainBytes()).isLessThan(r.naiveBytes());
        assertThat(r.batchedTotalBytes()).isLessThan(r.naiveBytes());
    }

    @Test
    void partialLastBatchIsStillCounted() {
        MiniComparison.Result r = MiniComparison.compare(250, 100);   // 100 + 100 + 50
        assertThat(r.batchedBlocks()).isEqualTo(4);                    // genesis + 3 batches
        assertThat(r.naiveBlocks()).isEqualTo(251);
    }
}
