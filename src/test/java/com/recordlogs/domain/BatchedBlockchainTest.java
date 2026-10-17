package com.recordlogs.domain;

import com.recordlogs.merkle.MerkleTree;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BatchedBlockchainTest {

    private static final int BATCH_SIZE = 4;
    private static final String FAKE_ROOT = "f".repeat(64);

    private BatchedBlockchain bc;

    /** 10 logs with batch size 4 => batches [log 0-3], [log 4-7], [log 8-9]; blocks = genesis + 3. */
    @BeforeEach
    void setUp() {
        bc = new BatchedBlockchain(BATCH_SIZE);
        for (int i = 0; i < 10; i++) {
            bc.addLog("log " + i);
        }
        bc.flush();
    }

    // ---------------------------------------------------------------- helpers

    private BatchedBlockchain forge(List<Block> blocks, List<StoredBatch> batches) {
        return BatchedBlockchain.fromStored(Blockchain.fromBlocks(blocks), batches, BATCH_SIZE);
    }

    private List<StoredBatch> replaceLogs(int batchIndex, List<String> newLogs) {
        List<StoredBatch> copy = new ArrayList<>(bc.getBatches());
        copy.set(batchIndex, new StoredBatch(newLogs, copy.get(batchIndex).leafHashes()));
        return copy;
    }

    private List<String> logsOf(int batchIndex) {
        return new ArrayList<>(bc.getBatches().get(batchIndex).logs());
    }

    // ---------------------------------------------------------------- batching

    @Test
    void logsAreBufferedUntilTheBatchIsFull() {
        BatchedBlockchain fresh = new BatchedBlockchain(3);
        assertThat(fresh.addLog("one").isPresent()).isFalse();
        assertThat(fresh.addLog("two").isPresent()).isFalse();
        assertThat(fresh.getPendingCount()).isEqualTo(2);
        assertThat(fresh.getBlocks()).hasSize(1);              // still only genesis

        Optional<Block> sealed = fresh.addLog("three");
        assertThat(sealed.isPresent()).isTrue();
        assertThat(fresh.getPendingCount()).isEqualTo(0);
        assertThat(fresh.getBatchCount()).isEqualTo(1);
        assertThat(fresh.getBlocks()).hasSize(2);
    }

    @Test
    void sealedBlockStoresOnlyRootAndCount() {
        BatchedBlockchain fresh = new BatchedBlockchain(3);
        fresh.addLog("one");
        fresh.addLog("two");
        Block block = fresh.addLog("three").get();

        Optional<BatchHeader> header = BatchHeader.tryParse(block.getData());
        assertThat(header.isPresent()).isTrue();
        assertThat(header.get().logCount()).isEqualTo(3);
        assertThat(header.get().merkleRoot())
                .isEqualTo(MerkleTree.of(List.of("one", "two", "three")).getRoot());
        // the raw logs are NOT in the block: only the root and the count are
        assertThat(block.getData().contains("one")).isFalse();
        assertThat(block.getData().contains("two")).isFalse();
    }

    @Test
    void flushSealsAPartialBatchAndIsANoOpWhenEmpty() {
        BatchedBlockchain fresh = new BatchedBlockchain(10);
        assertThat(fresh.flush().isPresent()).isFalse();       // nothing buffered
        fresh.addLog("only one");
        Optional<Block> sealed = fresh.flush();
        assertThat(sealed.isPresent()).isTrue();
        assertThat(BatchHeader.tryParse(sealed.get().getData()).get().logCount()).isEqualTo(1);
        assertThat(fresh.flush().isPresent()).isFalse();
    }

    @Test
    void untouchedBatchedChainIsValid() {
        assertThat(bc.getBatchCount()).isEqualTo(3);
        assertThat(bc.getBlocks()).hasSize(4);
        assertThat(bc.getPendingCount()).isEqualTo(0);
        assertThat(bc.validate().valid()).isTrue();
        assertThat(bc.validate(bc.createAnchor()).valid()).isTrue();
    }

    @Test
    void rejectsInvalidInput() {
        assertThatThrownBy(() -> new BatchedBlockchain(0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> bc.addLog(null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> bc.addLog("   ")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> BatchedBlockchain.fromStored(new Blockchain(), List.of(), 0))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void snapshotsCannotBeModified() {
        assertThatThrownBy(() -> bc.getBatches().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> bc.getBatches().get(0).logs().add("x"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> bc.getBlocks().clear()).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void cannotAppendToAnOutOfSyncLoadedChain() {
        List<StoredBatch> missingLast = new ArrayList<>(bc.getBatches());
        missingLast.remove(2);
        BatchedBlockchain broken = forge(new ArrayList<>(bc.getBlocks()), missingLast);

        assertThatThrownBy(() -> {
            for (int i = 0; i < BATCH_SIZE; i++) {
                broken.addLog("new " + i);
            }
        }).isInstanceOf(IllegalStateException.class);
    }

    // ---------------------------------------------------------------- verifyLog

    @Test
    void verifyLogIsTrueForEveryIntactLog() {
        int[] counts = {4, 4, 2};
        for (int batch = 0; batch < counts.length; batch++) {
            for (int i = 0; i < counts[batch]; i++) {
                assertThat(bc.verifyLog(batch, i)).as("batch " + batch + " log " + i).isTrue();
            }
        }
    }

    @Test
    void verifyLogFlagsOnlyTheEditedLog() {
        List<String> edited = logsOf(1);
        edited.set(2, "TAMPERED");
        BatchedBlockchain forged = forge(new ArrayList<>(bc.getBlocks()), replaceLogs(1, edited));

        assertThat(forged.verifyLog(1, 2)).isFalse();
        assertThat(forged.verifyLog(1, 0)).isTrue();
        assertThat(forged.verifyLog(1, 1)).isTrue();
        assertThat(forged.verifyLog(1, 3)).isTrue();
        assertThat(forged.verifyLog(0, 0)).isTrue();
    }

    @Test
    void verifyLogIsFalseForDeletedAndMovedLogs() {
        List<String> shorter = logsOf(0);
        shorter.remove(1);
        BatchedBlockchain deleted = forge(new ArrayList<>(bc.getBlocks()), replaceLogs(0, shorter));
        assertThat(deleted.verifyLog(0, 0)).isTrue();          // before the gap
        assertThat(deleted.verifyLog(0, 1)).isFalse();         // shifted
        assertThat(deleted.verifyLog(0, 3)).isFalse();         // no longer there

        List<String> swapped = logsOf(1);
        Collections.swap(swapped, 1, 3);
        BatchedBlockchain moved = forge(new ArrayList<>(bc.getBlocks()), replaceLogs(1, swapped));
        assertThat(moved.verifyLog(1, 1)).isFalse();
        assertThat(moved.verifyLog(1, 3)).isFalse();
        assertThat(moved.verifyLog(1, 0)).isTrue();
    }

    @Test
    void verifyLogIsFalseWhenTheOnChainRootWasForged() {
        List<Block> blocks = new ArrayList<>(bc.getBlocks());
        Block last = blocks.get(3);
        blocks.set(3, new Block(last.getIndex(), last.getTimestamp(), last.getPreviousHash(),
                new BatchHeader(FAKE_ROOT, 2).toData()));       // rehashed, so the block is self-consistent
        BatchedBlockchain forged = forge(blocks, new ArrayList<>(bc.getBatches()));

        assertThat(forged.verifyLog(2, 0)).isFalse();
        assertThat(forged.verifyLog(2, 1)).isFalse();
        assertThat(forged.verifyLog(0, 0)).isTrue();            // other batches unaffected
    }

    @Test
    void verifyLogRejectsIndexesThatDoNotExist() {
        assertThatThrownBy(() -> bc.verifyLog(-1, 0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> bc.verifyLog(3, 0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> bc.verifyLog(0, -1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> bc.verifyLog(0, 4)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> bc.verifyLog(2, 2)).isInstanceOf(IllegalArgumentException.class);
    }

    // ---------------------------------------------------------------- validate(): log tampering

    @Test
    void editedLogIsReportedWithExactBatchAndEntry() {
        List<String> edited = logsOf(1);
        edited.set(2, "TAMPERED");                              // batch 1, entry 2 (= "log 6")

        BatchValidationResult result =
                forge(new ArrayList<>(bc.getBlocks()), replaceLogs(1, edited)).validate();

        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(BatchValidationResult.Reason.LOG_EDITED);
        assertThat(result.batchIndex()).isEqualTo(1);
        assertThat(result.entryIndexes()).isEqualTo(List.of(2));
    }

    @Test
    void deletedLogIsReportedWithExactBatchAndEntry() {
        List<String> shorter = logsOf(0);
        shorter.remove(1);                                      // batch 0, entry 1 (= "log 1")

        BatchValidationResult result =
                forge(new ArrayList<>(bc.getBlocks()), replaceLogs(0, shorter)).validate();

        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(BatchValidationResult.Reason.LOG_DELETED);
        assertThat(result.batchIndex()).isEqualTo(0);
        assertThat(result.entryIndexes()).isEqualTo(List.of(1));
    }

    @Test
    void addedLogIsReportedWithExactBatchAndEntry() {
        List<String> longer = logsOf(0);
        longer.add(2, "INJECTED");                              // inserted at batch 0, entry 2

        BatchValidationResult result =
                forge(new ArrayList<>(bc.getBlocks()), replaceLogs(0, longer)).validate();

        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(BatchValidationResult.Reason.LOG_ADDED);
        assertThat(result.batchIndex()).isEqualTo(0);
        assertThat(result.entryIndexes()).isEqualTo(List.of(2));
    }

    @Test
    void reorderedLogsAreReportedWithExactBatchAndEntries() {
        List<String> swapped = logsOf(1);
        Collections.swap(swapped, 1, 3);                        // batch 1, entries 1 and 3 exchanged

        BatchValidationResult result =
                forge(new ArrayList<>(bc.getBlocks()), replaceLogs(1, swapped)).validate();

        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(BatchValidationResult.Reason.LOGS_REORDERED);
        assertThat(result.batchIndex()).isEqualTo(1);
        assertThat(result.entryIndexes()).isEqualTo(List.of(1, 3));
    }

    @Test
    void firstProblemInChainOrderIsReported() {
        List<String> editedLate = logsOf(2);
        editedLate.set(0, "TAMPERED");
        List<String> editedEarly = logsOf(0);
        editedEarly.set(3, "TAMPERED");
        List<StoredBatch> batches = new ArrayList<>(bc.getBatches());
        batches.set(2, new StoredBatch(editedLate, batches.get(2).leafHashes()));
        batches.set(0, new StoredBatch(editedEarly, batches.get(0).leafHashes()));

        BatchValidationResult result = forge(new ArrayList<>(bc.getBlocks()), batches).validate();

        assertThat(result.batchIndex()).isEqualTo(0);
        assertThat(result.entryIndexes()).isEqualTo(List.of(3));
    }

    // ---------------------------------------------------------------- validate(): root / chain tampering

    @Test
    void tamperedRootWithoutRehashIsCaughtByTheChain() {
        List<Block> blocks = new ArrayList<>(bc.getBlocks());
        Block original = blocks.get(2);                         // batch 1
        blocks.set(2, Block.restore(original.getIndex(), original.getTimestamp(), original.getPreviousHash(),
                new BatchHeader(FAKE_ROOT, 4).toData(), original.getHash()));

        BatchValidationResult result = forge(blocks, new ArrayList<>(bc.getBatches())).validate();

        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(BatchValidationResult.Reason.CHAIN_INVALID);
        assertThat(result.chainResult().reason()).isEqualTo(ValidationResult.Reason.HASH_MISMATCH);
        assertThat(result.batchIndex()).isEqualTo(1);
    }

    @Test
    void tamperedRootWithRehashInTheMiddleBreaksTheNextLink() {
        List<Block> blocks = new ArrayList<>(bc.getBlocks());
        Block original = blocks.get(1);                         // batch 0
        blocks.set(1, new Block(original.getIndex(), original.getTimestamp(), original.getPreviousHash(),
                new BatchHeader(FAKE_ROOT, 4).toData()));

        BatchValidationResult result = forge(blocks, new ArrayList<>(bc.getBatches())).validate();

        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(BatchValidationResult.Reason.CHAIN_INVALID);
        assertThat(result.chainResult().reason()).isEqualTo(ValidationResult.Reason.LINK_BROKEN);
        assertThat(result.batchIndex()).isEqualTo(1);           // the link breaks at the next batch's block
    }

    @Test
    void tamperedRootInTheLastBlockIsCaughtEvenThoughTheChainAloneIsFooled() {
        List<Block> blocks = new ArrayList<>(bc.getBlocks());
        Block last = blocks.get(3);                             // batch 2: nothing after it to break
        blocks.set(3, new Block(last.getIndex(), last.getTimestamp(), last.getPreviousHash(),
                new BatchHeader(FAKE_ROOT, 2).toData()));

        // the plain chain accepts this (classic last-block weakness) ...
        assertThat(Blockchain.fromBlocks(blocks).validate().valid()).isTrue();

        // ... the batched validation does not: the stored Merkle data cannot reproduce the forged root
        BatchValidationResult result = forge(blocks, new ArrayList<>(bc.getBatches())).validate();
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(BatchValidationResult.Reason.ROOT_MISMATCH);
        assertThat(result.batchIndex()).isEqualTo(2);
    }

    @Test
    void malformedBlockDataIsReported() {
        List<Block> blocks = new ArrayList<>(bc.getBlocks());
        Block last = blocks.get(3);
        blocks.set(3, new Block(last.getIndex(), last.getTimestamp(), last.getPreviousHash(), "garbage"));

        BatchValidationResult result = forge(blocks, new ArrayList<>(bc.getBatches())).validate();

        assertThat(result.reason()).isEqualTo(BatchValidationResult.Reason.MALFORMED_BLOCK_DATA);
        assertThat(result.batchIndex()).isEqualTo(2);
    }

    @Test
    void editingBothALogAndItsLeafHashIsStillDetectedButNotLocated() {
        StoredBatch original = bc.getBatches().get(1);
        List<String> logs = new ArrayList<>(original.logs());
        List<String> hashes = new ArrayList<>(original.leafHashes());
        logs.set(2, "TAMPERED");
        hashes.set(2, MerkleTree.leafHash("TAMPERED"));          // attacker also fixes the index
        List<StoredBatch> batches = new ArrayList<>(bc.getBatches());
        batches.set(1, new StoredBatch(logs, hashes));

        BatchValidationResult result = forge(new ArrayList<>(bc.getBlocks()), batches).validate();

        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(BatchValidationResult.Reason.ROOT_MISMATCH);
        assertThat(result.batchIndex()).isEqualTo(1);
        assertThat(result.entryIndexes()).isEqualTo(List.of());  // cannot say which entry
    }

    @Test
    void alteredLeafHashIndexAloneIsDetected() {
        StoredBatch original = bc.getBatches().get(0);
        List<String> hashes = new ArrayList<>(original.leafHashes());
        hashes.set(1, "0".repeat(64));
        List<StoredBatch> batches = new ArrayList<>(bc.getBatches());
        batches.set(0, new StoredBatch(original.logs(), hashes));

        BatchValidationResult result = forge(new ArrayList<>(bc.getBlocks()), batches).validate();

        assertThat(result.reason()).isEqualTo(BatchValidationResult.Reason.ROOT_MISMATCH);
        assertThat(result.batchIndex()).isEqualTo(0);
    }

    @Test
    void missingBatchDataIsDetected() {
        List<StoredBatch> batches = new ArrayList<>(bc.getBatches());
        batches.remove(2);

        BatchValidationResult result = forge(new ArrayList<>(bc.getBlocks()), batches).validate();

        assertThat(result.reason()).isEqualTo(BatchValidationResult.Reason.BATCH_DATA_MISSING);
        assertThat(result.batchIndex()).isEqualTo(2);
    }

    @Test
    void orphanBatchDataIsDetected() {
        List<Block> blocks = new ArrayList<>(bc.getBlocks());
        blocks.remove(3);                                        // last block gone, its raw data remains

        BatchValidationResult result = forge(blocks, new ArrayList<>(bc.getBatches())).validate();

        assertThat(result.reason()).isEqualTo(BatchValidationResult.Reason.BATCH_DATA_ORPHAN);
        assertThat(result.batchIndex()).isEqualTo(2);
    }

    // ---------------------------------------------------------------- ChainAnchor (truncation)

    @Test
    void anchorCatchesTruncationThatPlainValidationMisses() {
        ChainAnchor anchor = bc.createAnchor();                  // head = batch 2's block

        // Attacker drops the last block AND its raw data, so everything left is consistent.
        List<Block> blocks = new ArrayList<>(bc.getBlocks());
        blocks.remove(3);
        List<StoredBatch> batches = new ArrayList<>(bc.getBatches());
        batches.remove(2);
        BatchedBlockchain truncated = forge(blocks, batches);

        assertThat(truncated.validate().valid()).isTrue();       // the attack works without an anchor

        BatchValidationResult result = truncated.validate(anchor);
        assertThat(result.valid()).isFalse();
        assertThat(result.reason()).isEqualTo(BatchValidationResult.Reason.CHAIN_INVALID);
        assertThat(result.chainResult().reason()).isEqualTo(ValidationResult.Reason.TRUNCATED);
        assertThat(result.batchIndex()).isEqualTo(2);            // first missing batch
    }

    @Test
    void chainGrownPastTheAnchorIsStillValid() {
        ChainAnchor anchor = bc.createAnchor();
        for (int i = 10; i < 17; i++) {
            bc.addLog("log " + i);
        }
        bc.flush();

        assertThat(bc.getBatchCount()).isEqualTo(5);
        assertThat(bc.validate(anchor).valid()).isTrue();
    }

    @Test
    void anchorValidationStillReportsLogTamperingFirst() {
        ChainAnchor anchor = bc.createAnchor();
        List<String> edited = logsOf(1);
        edited.set(0, "TAMPERED");

        BatchValidationResult result =
                forge(new ArrayList<>(bc.getBlocks()), replaceLogs(1, edited)).validate(anchor);

        assertThat(result.reason()).isEqualTo(BatchValidationResult.Reason.LOG_EDITED);
        assertThat(result.batchIndex()).isEqualTo(1);
        assertThat(result.entryIndexes()).isEqualTo(List.of(0));
    }

    @Test
    void nullAnchorIsRejected() {
        assertThatThrownBy(() -> bc.validate(null)).isInstanceOf(NullPointerException.class);
    }
}
