package com.recordlogs.domain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BlockchainTest {

    private Blockchain chain;

    @BeforeEach
    void setUp() {
        chain = new Blockchain();
        for (int i = 1; i <= 5; i++) {
            chain.addBlock("log entry " + i);
        }
    }

    /** Builds a correctly linked chain with exact, caller-chosen timestamps (genesis first). */
    private static List<Block> manualChain(long... timestamps) {
        List<Block> list = new ArrayList<>();
        String prev = Block.GENESIS_PREVIOUS_HASH;
        for (int i = 0; i < timestamps.length; i++) {
            Block b = new Block(i, timestamps[i], prev, i == 0 ? "GENESIS" : "log " + i);
            list.add(b);
            prev = b.getHash();
        }
        return list;
    }

    // ---------------------------------------------------------------- basics

    @Test
    void newChainStartsWithGenesis() {
        Blockchain fresh = new Blockchain();
        assertThat(fresh.size()).isEqualTo(1);
        assertThat(fresh.getLatest().getPreviousHash()).isEqualTo(Block.GENESIS_PREVIOUS_HASH);
        assertThat(fresh.validate().valid()).isTrue();
    }

    @Test
    void untouchedChainIsValid() {
        assertThat(chain.size()).isEqualTo(6);
        assertThat(chain.validate().valid()).isTrue();
    }

    @Test
    void blocksAreLinkedByHash() {
        List<Block> blocks = chain.getBlocks();
        for (int i = 1; i < blocks.size(); i++) {
            assertThat(blocks.get(i).getPreviousHash()).isEqualTo(blocks.get(i - 1).getHash());
        }
    }

    @Test
    void snapshotCannotBeModified() {
        assertThatThrownBy(() -> chain.getBlocks().clear())
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void fromBlocksRejectsEmptyList() {
        assertThatThrownBy(() -> Blockchain.fromBlocks(List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // ------------------------------------------------- tampering (validate())

    @Test
    void editingLogDataIsDetectedAtThatBlock() {
        List<Block> copy = new ArrayList<>(chain.getBlocks());
        Block orig = copy.get(2);
        copy.set(2, Block.restore(orig.getIndex(), orig.getTimestamp(),
                orig.getPreviousHash(), "TAMPERED", orig.getHash()));

        ValidationResult result = Blockchain.fromBlocks(copy).validate();

        assertThat(result.valid()).isFalse();
        assertThat(result.failedPosition()).isEqualTo(2);
        assertThat(result.reason()).isEqualTo(ValidationResult.Reason.HASH_MISMATCH);
    }

    @Test
    void smartAttackerRecomputingHashIsCaughtAtNextBlock() {
        // Attacker edits block 2 AND recomputes its hash so block 2 looks self-consistent...
        List<Block> copy = new ArrayList<>(chain.getBlocks());
        Block orig = copy.get(2);
        copy.set(2, new Block(orig.getIndex(), orig.getTimestamp(), orig.getPreviousHash(), "TAMPERED"));

        ValidationResult result = Blockchain.fromBlocks(copy).validate();

        // ...but block 3 still points at the OLD hash, so the link breaks there.
        assertThat(result.valid()).isFalse();
        assertThat(result.failedPosition()).isEqualTo(3);
        assertThat(result.reason()).isEqualTo(ValidationResult.Reason.LINK_BROKEN);
    }

    @Test
    void deletingABlockIsDetected() {
        List<Block> copy = new ArrayList<>(chain.getBlocks());
        copy.remove(2);

        ValidationResult result = Blockchain.fromBlocks(copy).validate();

        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(ValidationResult.Reason.INDEX_MISMATCH);
    }

    @Test
    void reorderedBlocksAreDetected() {
        List<Block> copy = new ArrayList<>(chain.getBlocks());
        Collections.swap(copy, 2, 3);

        ValidationResult result = Blockchain.fromBlocks(copy).validate();

        // Position 2 now holds the block with index 3 (expected 2).
        assertThat(result.valid()).isFalse();
        assertThat(result.failedPosition()).isEqualTo(2);
        assertThat(result.reason()).isEqualTo(ValidationResult.Reason.INDEX_MISMATCH);
    }

    @Test
    void timestampRegressionIsDetected() {
        // Every block is internally valid and correctly linked; only block 2 is older than block 1.
        Blockchain forged = Blockchain.fromBlocks(manualChain(1000L, 2000L, 1500L));

        ValidationResult result = forged.validate();

        assertThat(result.valid()).isFalse();
        assertThat(result.failedPosition()).isEqualTo(2);
        assertThat(result.reason()).isEqualTo(ValidationResult.Reason.TIMESTAMP_REGRESSION);
    }

    @Test
    void invalidGenesisWithWrongIndexIsDetected() {
        Block badGenesis = new Block(1, 1000L, Block.GENESIS_PREVIOUS_HASH, "GENESIS");

        ValidationResult result = Blockchain.fromBlocks(List.of(badGenesis)).validate();

        assertThat(result.valid()).isFalse();
        assertThat(result.failedPosition()).isEqualTo(0);
        assertThat(result.reason()).isEqualTo(ValidationResult.Reason.INVALID_GENESIS);
    }

    @Test
    void invalidGenesisWithWrongPreviousHashIsDetected() {
        Block badGenesis = new Block(0, 1000L, "a".repeat(64), "GENESIS");

        ValidationResult result = Blockchain.fromBlocks(List.of(badGenesis)).validate();

        assertThat(result.valid()).isFalse();
        assertThat(result.failedPosition()).isEqualTo(0);
        assertThat(result.reason()).isEqualTo(ValidationResult.Reason.INVALID_GENESIS);
    }

    // ------------------------------------------- tail truncation (anchor)

    @Test
    void createAnchorSnapshotsTheCurrentHead() {
        ChainAnchor anchor = chain.createAnchor();

        assertThat(anchor.height()).isEqualTo(5);
        assertThat(anchor.latestHash()).isEqualTo(chain.getLatest().getHash());
    }

    @Test
    void tailTruncationPassesPlainValidateButIsCaughtByAnchor() {
        ChainAnchor anchor = chain.createAnchor();   // head is block 5

        // Attacker deletes the last 2 blocks (the evidence of the final events).
        List<Block> copy = new ArrayList<>(chain.getBlocks());
        copy.remove(5);
        copy.remove(4);
        Blockchain truncated = Blockchain.fromBlocks(copy);
        assertThat(truncated.size()).isEqualTo(4);

        // Without an anchor the shorter chain looks perfectly fine: this IS the attack.
        assertThat(truncated.validate().valid()).isTrue();

        // With the anchor it is caught.
        ValidationResult result = truncated.validate(anchor);
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(ValidationResult.Reason.TRUNCATED);
        assertThat(result.failedPosition()).isEqualTo(4);   // first missing position
    }

    @Test
    void truncatingDownToGenesisOnlyIsCaughtByAnchor() {
        ChainAnchor anchor = chain.createAnchor();
        Blockchain truncated = Blockchain.fromBlocks(List.of(chain.getBlock(0)));

        assertThat(truncated.validate().valid()).isTrue();
        assertThat(truncated.validate(anchor).reason()).isEqualTo(ValidationResult.Reason.TRUNCATED);
    }

    @Test
    void chainLongerThanAnchorIsStillValid() {
        ChainAnchor anchor = chain.createAnchor();   // taken at 6 blocks

        chain.addBlock("log entry 6");
        chain.addBlock("log entry 7");
        chain.addBlock("log entry 8");

        assertThat(chain.size()).isEqualTo(9);
        assertThat(chain.validate(anchor).valid()).isTrue();
    }

    @Test
    void intactChainIsValidAgainstItsOwnAnchor() {
        assertThat(chain.validate(chain.createAnchor()).valid()).isTrue();
    }

    @Test
    void headRewrittenAtAnchorHeightIsCaught() {
        ChainAnchor anchor = chain.createAnchor();   // height 5

        // Attacker cuts the last block and appends a different, internally valid one.
        List<Block> copy = new ArrayList<>(chain.getBlocks());
        Block fourth = copy.get(4);
        copy.set(5, new Block(5, chain.getLatest().getTimestamp(), fourth.getHash(), "FORGED"));
        Blockchain rewritten = Blockchain.fromBlocks(copy);

        assertThat(rewritten.validate().valid()).isTrue();   // consistent on its own

        ValidationResult result = rewritten.validate(anchor);
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(ValidationResult.Reason.TRUNCATED);
        assertThat(result.failedPosition()).isEqualTo(5);
    }

    @Test
    void anchorValidationStillReportsInternalTamperingFirst() {
        ChainAnchor anchor = chain.createAnchor();

        List<Block> copy = new ArrayList<>(chain.getBlocks());
        Block orig = copy.get(2);
        copy.set(2, Block.restore(orig.getIndex(), orig.getTimestamp(),
                orig.getPreviousHash(), "TAMPERED", orig.getHash()));

        ValidationResult result = Blockchain.fromBlocks(copy).validate(anchor);

        assertThat(result.valid()).isFalse();
        assertThat(result.failedPosition()).isEqualTo(2);
        assertThat(result.reason()).isEqualTo(ValidationResult.Reason.HASH_MISMATCH);
    }

    @Test
    void nullAnchorIsRejected() {
        assertThatThrownBy(() -> chain.validate(null))
                .isInstanceOf(NullPointerException.class);
    }
}
