package com.recordlogs.domain;

import com.recordlogs.merkle.MerkleProof;
import com.recordlogs.merkle.MerkleTree;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * The optimized chain: logs are buffered, and every full batch becomes ONE block whose data is just
 * {@code MERKLE|<root>|<count>} (see {@link BatchHeader}) instead of one block per log.
 *
 * <p>Built on top of {@link Blockchain}/{@link Block} by composition: block 0 is the genesis block,
 * batch {@code i} lives in block position {@code i + 1}. The raw logs stay OFF-chain in memory (a
 * {@link StoredBatch} per batch; persistence arrives in Phase 4).
 *
 * <p><b>Exposure window:</b> logs still in the buffer are not on the chain yet and therefore not
 * tamper-evident. Smaller batches shrink that window, larger batches save more space.
 *
 * <p><b>Creating vs. loading:</b> the constructors are only for a brand-new chain; a persisted one
 * must be loaded via {@link #fromStored(Blockchain, List, int)} (same rule as {@link Blockchain}).
 */
public class BatchedBlockchain {

    public static final int DEFAULT_BATCH_SIZE = 100;

    private static final Logger log = LoggerFactory.getLogger(BatchedBlockchain.class);

    private final int batchSize;
    private final Blockchain chain;
    private final List<StoredBatch> batches = new ArrayList<>();
    private final Map<Integer, MerkleTree> treeCache = new HashMap<>();
    private final List<String> buffer = new ArrayList<>();

    /** Brand-new chain with {@link #DEFAULT_BATCH_SIZE}. */
    public BatchedBlockchain() {
        this(DEFAULT_BATCH_SIZE);
    }

    /** Brand-new chain (fresh genesis block) that seals a block every {@code batchSize} logs. */
    public BatchedBlockchain(int batchSize) {
        this(requireValidBatchSize(batchSize), new Blockchain(), List.of());
    }

    private BatchedBlockchain(int batchSize, Blockchain chain, List<StoredBatch> stored) {
        this.batchSize = batchSize;
        this.chain = chain;
        this.batches.addAll(stored);
    }

    /**
     * Rebuilds a batched chain from stored data (the correct way to load a persisted chain).
     * Deliberately does NOT validate: call {@link #validate()} to find out if it was tampered with.
     * The log buffer starts empty.
     */
    public static BatchedBlockchain fromStored(Blockchain chain, List<StoredBatch> batches, int batchSize) {
        Objects.requireNonNull(chain, "chain must not be null");
        Objects.requireNonNull(batches, "batches must not be null");
        return new BatchedBlockchain(requireValidBatchSize(batchSize), chain, List.copyOf(batches));
    }

    private static int requireValidBatchSize(int batchSize) {
        if (batchSize < 1) {
            throw new IllegalArgumentException("batchSize must be >= 1");
        }
        return batchSize;
    }

    // ------------------------------------------------------------------ writing

    /**
     * Buffers one log. When the buffer reaches the batch size, the batch is sealed into a block.
     *
     * @return the new block if this call sealed a batch, otherwise empty
     */
    public synchronized Optional<Block> addLog(String logLine) {
        if (logLine == null || logLine.isBlank()) {
            throw new IllegalArgumentException("log must not be blank");
        }
        buffer.add(logLine);
        return buffer.size() >= batchSize ? Optional.of(sealBuffer()) : Optional.empty();
    }

    /** Seals whatever is in the buffer as a (possibly smaller) batch; no-op if the buffer is empty. */
    public synchronized Optional<Block> flush() {
        return buffer.isEmpty() ? Optional.empty() : Optional.of(sealBuffer());
    }

    private Block sealBuffer() {
        if (batches.size() != chain.size() - 1) {
            throw new IllegalStateException(
                    "stored batches and blocks are out of sync; run validate() before appending");
        }
        List<String> logs = List.copyOf(buffer);
        MerkleTree tree = MerkleTree.of(logs);
        Block block = chain.addBlock(new BatchHeader(tree.getRoot(), logs.size()).toData());
        batches.add(new StoredBatch(logs, tree.getLeafHashes()));
        treeCache.put(batches.size() - 1, tree);
        buffer.clear();
        log.debug("Sealed batch {} with {} logs into {}", batches.size() - 1, logs.size(), block);
        return block;
    }

    // ------------------------------------------------------------------ verifying

    /**
     * Checks one log with a Merkle proof against the root stored on-chain: O(log n) hashing once the
     * batch's tree is cached.
     *
     * <p>Returns false if the log was changed, moved or removed, if the batch's Merkle data does not
     * reproduce the on-chain root, or if the block holding the root fails its own hash check. It does
     * NOT walk the whole chain: run {@link #validate()} for full chain integrity. A false result
     * means "cannot be proven intact", it does not say why; {@link #validate()} gives the diagnosis.
     *
     * @throws IllegalArgumentException if {@code batchIndex} or {@code logIndex} does not exist
     */
    public synchronized boolean verifyLog(int batchIndex, int logIndex) {
        if (batchIndex < 0 || batchIndex >= batches.size()) {
            throw new IllegalArgumentException("batch " + batchIndex + " does not exist");
        }
        if (batchIndex + 1 >= chain.size()) {
            return false;                                   // raw data with no block behind it
        }
        Block block = chain.getBlock(batchIndex + 1);
        Optional<BatchHeader> header = BatchHeader.tryParse(block.getData());
        if (!block.hasValidHash() || header.isEmpty()) {
            return false;
        }
        if (logIndex < 0 || logIndex >= header.get().logCount()) {
            throw new IllegalArgumentException("log " + logIndex + " does not exist in batch " + batchIndex);
        }
        StoredBatch stored = batches.get(batchIndex);
        if (logIndex >= stored.logs().size()) {
            return false;                                   // entry was deleted
        }
        MerkleTree tree = treeFor(batchIndex, stored);
        if (tree == null || logIndex >= tree.getLeafCount()) {
            return false;
        }
        MerkleProof proof = tree.generateProof(logIndex);
        return MerkleProof.verify(stored.logs().get(logIndex), proof, header.get().merkleRoot());
    }

    private MerkleTree treeFor(int batchIndex, StoredBatch stored) {
        MerkleTree cached = treeCache.get(batchIndex);
        if (cached != null) {
            return cached;
        }
        if (stored.leafHashes().isEmpty()) {
            return null;
        }
        MerkleTree built = MerkleTree.fromLeafHashes(stored.leafHashes());
        treeCache.put(batchIndex, built);
        return built;
    }

    /**
     * Validates the underlying chain AND every batch against its stored raw logs. Reports the FIRST
     * problem found, in chain order. Cannot detect tail truncation of the chain: use
     * {@link #validate(ChainAnchor)} for that.
     */
    public synchronized BatchValidationResult validate() {
        return validateInternal(null);
    }

    /** Everything {@link #validate()} does, plus the {@link ChainAnchor} truncation check. */
    public synchronized BatchValidationResult validate(ChainAnchor trusted) {
        Objects.requireNonNull(trusted, "trusted anchor must not be null");
        return validateInternal(trusted);
    }

    private BatchValidationResult validateInternal(ChainAnchor anchor) {
        ValidationResult chainResult = (anchor == null) ? chain.validate() : chain.validate(anchor);
        if (!chainResult.valid()) {
            return BatchValidationResult.chainFailure(chainResult);
        }

        List<Block> blocks = chain.getBlocks();
        for (int position = 1; position < blocks.size(); position++) {
            int batchIndex = position - 1;
            Block block = blocks.get(position);

            if (batchIndex >= batches.size()) {
                return BatchValidationResult.batchFailure(BatchValidationResult.Reason.BATCH_DATA_MISSING,
                        batchIndex, "Block " + block.getIndex() + " exists but batch " + batchIndex
                                + " has no stored raw logs");
            }
            Optional<BatchHeader> parsed = BatchHeader.tryParse(block.getData());
            if (parsed.isEmpty()) {
                return BatchValidationResult.batchFailure(BatchValidationResult.Reason.MALFORMED_BLOCK_DATA,
                        batchIndex, "Block " + block.getIndex() + " does not contain a valid batch header");
            }
            BatchValidationResult problem = checkBatch(batchIndex, parsed.get(), batches.get(batchIndex));
            if (problem != null) {
                return problem;
            }
        }

        if (batches.size() > blocks.size() - 1) {
            return BatchValidationResult.batchFailure(BatchValidationResult.Reason.BATCH_DATA_ORPHAN,
                    blocks.size() - 1, "Raw batch data exists beyond the last block: blocks were removed");
        }
        return BatchValidationResult.ok();
    }

    /** @return null if the batch is intact, otherwise the first problem found in it. */
    private static BatchValidationResult checkBatch(int batchIndex, BatchHeader header, StoredBatch stored) {
        List<String> logs = stored.logs();

        // Fast path: recompute the root from the stored raw logs, exactly as when it was sealed.
        if (logs.size() == header.logCount()) {
            MerkleTree fromLogs = MerkleTree.of(logs);
            if (fromLogs.getRoot().equals(header.merkleRoot())) {
                if (!fromLogs.getLeafHashes().equals(stored.leafHashes())) {
                    return BatchValidationResult.batchFailure(BatchValidationResult.Reason.ROOT_MISMATCH,
                            batchIndex, "Batch " + batchIndex + ": logs match the root but the stored "
                                    + "leaf-hash index was altered");
                }
                return null;
            }
        }

        // Something is wrong. First make sure the stored leaf-hash index is itself authentic, i.e. it
        // reproduces the on-chain root; only then can it be used as the reference to locate the change.
        List<String> expected = stored.leafHashes();
        boolean indexAuthentic = expected.size() == header.logCount()
                && MerkleTree.fromLeafHashes(expected).getRoot().equals(header.merkleRoot());
        if (!indexAuthentic) {
            return BatchValidationResult.batchFailure(BatchValidationResult.Reason.ROOT_MISMATCH, batchIndex,
                    "Batch " + batchIndex + ": stored Merkle data does not reproduce the on-chain root "
                            + "(root or leaf-hash index tampered); the exact entry cannot be located");
        }

        BatchValidationResult located = locate(batchIndex, logs, expected);
        return located != null ? located
                : BatchValidationResult.batchFailure(BatchValidationResult.Reason.ROOT_MISMATCH, batchIndex,
                        "Batch " + batchIndex + ": logs do not reproduce the on-chain root");
    }

    /** Compares stored logs with the authentic leaf hashes and names the exact entries that differ. */
    private static BatchValidationResult locate(int batchIndex, List<String> logs, List<String> expected) {
        List<String> actual = new ArrayList<>(logs.size());
        for (String logLine : logs) {
            actual.add(MerkleTree.leafHash(logLine));
        }
        int stored = actual.size();
        int sealed = expected.size();

        if (stored == sealed) {
            List<Integer> changed = new ArrayList<>();
            for (int i = 0; i < sealed; i++) {
                if (!actual.get(i).equals(expected.get(i))) {
                    changed.add(i);
                }
            }
            if (changed.isEmpty()) {
                return null;
            }
            List<String> a = new ArrayList<>(actual);
            List<String> e = new ArrayList<>(expected);
            Collections.sort(a);
            Collections.sort(e);
            boolean sameLogsDifferentOrder = a.equals(e);
            return BatchValidationResult.entryFailure(
                    sameLogsDifferentOrder ? BatchValidationResult.Reason.LOGS_REORDERED
                                           : BatchValidationResult.Reason.LOG_EDITED,
                    batchIndex, changed,
                    "Batch " + batchIndex + ": " + (sameLogsDifferentOrder ? "logs reordered" : "log edited")
                            + " at entries " + changed);
        }
        if (stored < sealed) {
            List<Integer> missing = unmatchedPositions(expected, actual);
            return BatchValidationResult.entryFailure(BatchValidationResult.Reason.LOG_DELETED, batchIndex,
                    missing, "Batch " + batchIndex + ": " + (sealed - stored) + " log(s) deleted, "
                            + "first missing entry at position " + (missing.isEmpty() ? "?" : missing.get(0)));
        }
        List<Integer> extra = unmatchedPositions(actual, expected);
        return BatchValidationResult.entryFailure(BatchValidationResult.Reason.LOG_ADDED, batchIndex,
                extra, "Batch " + batchIndex + ": " + (stored - sealed) + " log(s) added, "
                        + "first extra entry at position " + (extra.isEmpty() ? "?" : extra.get(0)));
    }

    /**
     * Positions in {@code longer} that have no counterpart when {@code shorter} is matched as a
     * subsequence (greedy, left to right). Exact for pure insertions/deletions; with identical
     * neighbouring entries the reported position may be any of the equivalent ones.
     */
    private static List<Integer> unmatchedPositions(List<String> longer, List<String> shorter) {
        List<Integer> gaps = new ArrayList<>();
        int j = 0;
        for (int i = 0; i < longer.size(); i++) {
            if (j < shorter.size() && longer.get(i).equals(shorter.get(j))) {
                j++;
            } else {
                gaps.add(i);
            }
        }
        return gaps;
    }

    // ------------------------------------------------------------------ read access

    /** Snapshots the current chain head as a {@link ChainAnchor}; store it SEPARATELY from the blocks. */
    public synchronized ChainAnchor createAnchor() {
        return chain.createAnchor();
    }

    /** Read-only snapshot of the underlying chain's blocks (genesis first). */
    public synchronized List<Block> getBlocks() {
        return chain.getBlocks();
    }

    /** Read-only snapshot of the off-chain batch data, batch 0 first. */
    public synchronized List<StoredBatch> getBatches() {
        return Collections.unmodifiableList(new ArrayList<>(batches));
    }

    public synchronized int getBatchCount() {
        return batches.size();
    }

    /** Logs buffered but not yet sealed on the chain. */
    public synchronized int getPendingCount() {
        return buffer.size();
    }

    public int getBatchSize() {
        return batchSize;
    }
}
