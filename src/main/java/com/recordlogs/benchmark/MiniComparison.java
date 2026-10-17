package com.recordlogs.benchmark;

import com.recordlogs.domain.BatchedBlockchain;
import com.recordlogs.domain.Block;
import com.recordlogs.domain.Blockchain;
import com.recordlogs.domain.StoredBatch;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Random;

/**
 * Phase 2 console comparison: naive chain (one block per log) vs batched Merkle chain.
 * Counts blocks and stored bytes only. Full benchmarking (search and verification time, graphs)
 * comes in Phase 7.
 *
 * <p>"Bytes" means the UTF-8 size of each block serialized as
 * {@code index|timestamp|previousHash|data|hash} (hashes as hex text, the way they would sit in text
 * columns), plus, for the batched chain, the off-chain raw logs and the leaf-hash index.
 *
 * <p>Run: {@code java ... com.recordlogs.benchmark.MiniComparison [logCount] [batchSize]}
 * (defaults 10000 and 100), or run {@code MiniComparisonTest}.
 */
public final class MiniComparison {

    private MiniComparison() {
    }

    public record Result(int logCount, int batchSize,
                         int naiveBlocks, long naiveBytes,
                         int batchedBlocks, long batchedOnChainBytes,
                         long batchedRawLogBytes, long batchedLeafIndexBytes) {

        public long batchedTotalBytes() {
            return batchedOnChainBytes + batchedRawLogBytes + batchedLeafIndexBytes;
        }

        public double onChainReductionPercent() {
            return 100.0 * (naiveBytes - batchedOnChainBytes) / naiveBytes;
        }

        public double totalReductionPercent() {
            return 100.0 * (naiveBytes - batchedTotalBytes()) / naiveBytes;
        }
    }

    public static Result compare(int logCount, int batchSize) {
        List<String> logs = generateLogs(logCount, 42L);

        Blockchain naive = new Blockchain();
        for (String line : logs) {
            naive.addBlock(line);
        }

        BatchedBlockchain batched = new BatchedBlockchain(batchSize);
        for (String line : logs) {
            batched.addLog(line);
        }
        batched.flush();

        long naiveBytes = blocksBytes(naive.getBlocks());
        long onChain = blocksBytes(batched.getBlocks());
        long raw = 0;
        long leafIndex = 0;
        for (StoredBatch batch : batched.getBatches()) {
            for (String line : batch.logs()) {
                raw += utf8Length(line);
            }
            for (String h : batch.leafHashes()) {
                leafIndex += utf8Length(h);
            }
        }
        return new Result(logCount, batchSize, naive.size(), naiveBytes,
                batched.getBlocks().size(), onChain, raw, leafIndex);
    }

    public static void print(Result r, PrintStream out) {
        out.println();
        out.println("=== Record: naive chain vs batched Merkle chain ===");
        out.printf(Locale.ROOT, "logs: %,d   batch size: %,d%n", r.logCount(), r.batchSize());
        out.println("---------------------------------------------------------------");
        out.printf(Locale.ROOT, "Naive   (1 block per log)  blocks: %,8d   stored bytes: %,12d%n",
                r.naiveBlocks(), r.naiveBytes());
        out.printf(Locale.ROOT, "Batched (Merkle root only) blocks: %,8d   on-chain bytes: %,10d%n",
                r.batchedBlocks(), r.batchedOnChainBytes());
        out.printf(Locale.ROOT, "          + off-chain raw logs:               %,12d%n", r.batchedRawLogBytes());
        out.printf(Locale.ROOT, "          + leaf-hash index:                  %,12d%n", r.batchedLeafIndexBytes());
        out.printf(Locale.ROOT, "          = batched total:                    %,12d%n", r.batchedTotalBytes());
        out.println("---------------------------------------------------------------");
        out.printf(Locale.ROOT, "On-chain footprint reduction: %.1f%%   (blocks: %,d -> %,d)%n",
                r.onChainReductionPercent(), r.naiveBlocks(), r.batchedBlocks());
        out.printf(Locale.ROOT, "Total storage reduction:      %.1f%%   (raw logs are kept in both designs)%n",
                r.totalReductionPercent());
        out.println();
    }

    public static void main(String[] args) {
        int logCount = args.length > 0 ? Integer.parseInt(args[0]) : 10_000;
        int batchSize = args.length > 1 ? Integer.parseInt(args[1]) : 100;
        print(compare(logCount, batchSize), System.out);
    }

    // ------------------------------------------------------------------ helpers

    private static long blocksBytes(List<Block> blocks) {
        long total = 0;
        for (Block b : blocks) {
            total += utf8Length(b.getIndex() + "|" + b.getTimestamp() + "|" + b.getPreviousHash()
                    + "|" + b.getData() + "|" + b.getHash());
        }
        return total;
    }

    private static int utf8Length(String s) {
        return s.getBytes(StandardCharsets.UTF_8).length;
    }

    /** Deterministic, realistic-looking security logs (fixed seed, so results are reproducible). */
    static List<String> generateLogs(int count, long seed) {
        Random rnd = new Random(seed);
        String[] users = {"alice", "bob", "carol", "dave", "erin", "root", "admin", "svc-backup"};
        long time = 1_767_225_600_000L;   // 2026-01-01T00:00:00Z
        List<String> logs = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            time += 1 + rnd.nextInt(2000);
            int roll = rnd.nextInt(100);
            String event;
            String detail = "";
            if (roll < 55) {
                event = "LOGIN_OK";
            } else if (roll < 85) {
                event = "LOGIN_FAILED";
            } else if (roll < 95) {
                event = "FILE_DELETE";
                detail = " path=/var/data/file" + rnd.nextInt(5000);
            } else {
                event = "PRIV_CHANGE";
                detail = " role=admin";
            }
            String ip = (1 + rnd.nextInt(223)) + "." + rnd.nextInt(256) + "." + rnd.nextInt(256)
                    + "." + (1 + rnd.nextInt(254));
            logs.add(Instant.ofEpochMilli(time) + " host-" + (1 + rnd.nextInt(5)) + " " + event
                    + " user=" + users[rnd.nextInt(users.length)] + " ip=" + ip + detail);
        }
        return logs;
    }
}
