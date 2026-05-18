package handshake.node;

import handshake.database.Database;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Downloads full blocks from multiple peers in parallel.
 *
 * Works like a torrent client:
 *  - A shared WorkQueue holds (height, hash) pairs still needed
 *  - Each authenticated peer gets its own PeerWorker thread
 *  - PeerWorkers pull chunks from the WorkQueue, send GETDATA,
 *    receive BLOCK responses, and pass them to the DatabaseWriter
 *  - The DatabaseWriter is a single thread that serialises all DB writes
 *    (H2 embedded mode requires single-threaded writes)
 *  - If a peer drops, its in-progress chunk goes back to the WorkQueue
 *    and is picked up by another worker
 *
 * Usage:
 *   List<Peer> peers = HNSPeerManager.discoverPeers();
 *   BlockSyncCoordinator coordinator = new BlockSyncCoordinator(peers, db);
 *   coordinator.sync(); // blocks until all blocks are downloaded or all peers fail
 */
public class BlockSyncCoordinator {

    // -------------------------------------------------------------------------
    // Tuning constants
    // -------------------------------------------------------------------------

    /** Number of block heights each worker requests per GETDATA round-trip. */
    private static final int CHUNK_SIZE = 128;

    /** How long the DB writer waits for new work before checking if done. */
    private static final int WRITER_POLL_MS = 500;

    /** Max items in the DB write queue before workers pause. */
    private static final int WRITE_QUEUE_CAPACITY = 512;

    // -------------------------------------------------------------------------
    // Shared state
    // -------------------------------------------------------------------------

    /** Heights still to be downloaded, as (height, hash) pairs. */
    private final BlockingQueue<HeightHash> workQueue;

    /** Heights that have been successfully written to the database. */
    private final ConcurrentHashMap<Integer, Boolean> completed = new ConcurrentHashMap<>();

    /** Blocks ready to be written to the database. */
    private final BlockingQueue<WriteTask> writeQueue =
            new LinkedBlockingQueue<>(WRITE_QUEUE_CAPACITY);

    /** Total blocks to sync (for progress reporting). */
    private final int totalBlocks;

    /** Count of blocks written so far. */
    private final AtomicInteger writtenCount = new AtomicInteger(0);

    /** Set to true when a fatal error occurs to stop all workers. */
    private final AtomicBoolean fatalError = new AtomicBoolean(false);

    /** The database to write to. */
    private final Database db;

    /** All authenticated peers. */
    private final List<Peer> peers;

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    public BlockSyncCoordinator(List<Peer> peers, Database db) throws Exception {
        this.peers = peers;
        this.db    = db;

        // Build the work queue from block_data tip to header tip
        int blockTip  = db.getBlockDataTip();
        int headerTip = db.getTipHeight();
        int start      = blockTip + 1;

        if (start > headerTip) {
            this.workQueue   = new LinkedBlockingQueue<>();
            this.totalBlocks = 0;
            return;
        }

        this.totalBlocks = headerTip - start + 1;
        this.workQueue   = new LinkedBlockingQueue<>(totalBlocks);

        System.out.println("[BlockSync] Loading " + totalBlocks
                + " block hashes from database (height "
                + start + " to " + headerTip + ")...");

        // Load hashes in batches to avoid one giant DB query
        final int LOAD_BATCH = 10_000;
        for (int base = start; base <= headerTip; base += LOAD_BATCH) {
            int end = Math.min(base + LOAD_BATCH - 1, headerTip);
            for (int h = base; h <= end; h++) {
                byte[] hash = db.getHashAtHeight(h);
                if (hash != null)
                    workQueue.put(new HeightHash(h, hash));
            }
        }
        System.out.println("[BlockSync] Work queue ready. "
                + workQueue.size() + " blocks to fetch across "
                + peers.size() + " peers.");
    }

    /**
     * Expands the peer pool by sending GETADDR to each of the initial peers
     * and connecting (via brontide) to any new peers they advertise.
     *
     * Each peer's ADDR response can contain hundreds of addresses. We attempt
     * brontide connections to them concurrently, keeping up to MAX_EXTRA_PEERS
     * additional connections. All connections are fully encrypted — we skip
     * any address without a brontide key.
     */
    private void discoverMorePeers() {
        // Disabled — hsd nodes return 0 addresses to GETADDR, and opening
        // extra connections per attempt triggers rate limiting / bans.
    }

    // -------------------------------------------------------------------------
    // Main sync entry point
    // -------------------------------------------------------------------------

    /**
     * Runs the parallel block sync. Blocks until all blocks are downloaded
     * or all peers have failed permanently.
     *
     * @throws Exception if a fatal database error occurs
     */
    public void sync() throws Exception {
        if (totalBlocks == 0) {
            System.out.println("[BlockSync] Nothing to sync.");
            return;
        }

        // Expand peer pool via GETADDR before starting workers
        discoverMorePeers();

        // Start one PeerWorker thread per peer
        try (ExecutorService workerPool = Executors.newFixedThreadPool(peers.size())) {
            for (Peer peer : peers)
                workerPool.submit(new PeerWorker(peer));

            // Start the single database writer thread
            Thread writerThread = new Thread(this::runDatabaseWriter, "db-writer");
            writerThread.setDaemon(true);
            writerThread.start();

            // Progress reporter — prints every 30 seconds
            Thread progressThread = new Thread(this::runProgressReporter, "progress");
            progressThread.setDaemon(true);
            progressThread.start();

            // Wait for all workers to finish
            workerPool.shutdown();
            if (!workerPool.awaitTermination(Long.MAX_VALUE, TimeUnit.MILLISECONDS))
                System.out.println("[BlockSync] Worker pool did not terminate cleanly.");

            // Signal the writer that no more blocks are coming
            writeQueue.put(WriteTask.POISON);
            writerThread.join();
        }

        if (fatalError.get())
            throw new Exception("[BlockSync] Fatal database error during sync.");

        int remaining = workQueue.size();
        if (remaining > 0)
            System.out.println("[BlockSync] WARNING: " + remaining
                    + " blocks not downloaded (all peers failed).");
        else
            System.out.println("[BlockSync] Complete. "
                    + writtenCount.get() + " blocks written.");
    }

    // -------------------------------------------------------------------------
    // PeerWorker — one per peer, runs on its own thread
    // -------------------------------------------------------------------------

    private class PeerWorker implements Runnable {
        private final Peer peer;

        PeerWorker(Peer peer) {
            this.peer = peer;
        }

        @Override
        public void run() {
            String ip = peer.seed.ipAddress();
            // suppressed: worker starting

            HNSPeer hnsPeer = null; // null check needed in finally block
            try {
                // P2P handshake — guard against null brontide state
                if (peer.brontide == null) {
                    System.out.println("[" + ip + "] No brontide state — skipping.");
                    return;
                }
                hnsPeer = new HNSPeer(peer, peer.brontide);
                hnsPeer.handshake();
                hnsPeer.sendSendHeaders();
                hnsPeer.drainPendingMessages();

                // Pull chunks from the work queue and download them
                while (!fatalError.get()) {
                    List<HeightHash> chunk = takeChunk();
                    if (chunk == null) break; // queue empty — we're done

                    try {
                        downloadChunk(hnsPeer, chunk);
                    } catch (Exception e) {
                        String msg = e.getMessage() != null ? e.getMessage() : "";
                        boolean isExpectedDrop = msg.contains("Connection closed")
                                || msg.contains("timed out")
                                || msg.contains("reset")
                                || msg.contains("Broken pipe");
                        System.out.println("[" + ip + "] Error during chunk: "
                                + e.getClass().getSimpleName()
                                + ": " + msg);
                        if (!isExpectedDrop && !(e instanceof SecurityException))
                            System.out.println("[" + ip + "] Unexpected error: "
                                    + e.getClass().getName() + "\n"
                                    + java.util.Arrays.stream(e.getStackTrace())
                                    .limit(5)
                                    .map(StackTraceElement::toString)
                                    .collect(java.util.stream.Collectors.joining("\n\t", "\t", "")));
                        returnToQueue(chunk);
                        break;
                    }
                    hnsPeer.drainPendingMessages();
                }

            } catch (Exception e) {
                System.out.println("[" + ip + "] Worker failed: "
                        + e.getClass().getSimpleName()
                        + ": " + e.getMessage());
            } finally {
                if (hnsPeer != null)
                    try { hnsPeer.peer.socket.close(); } catch (Exception ignored) {}
                // suppressed: worker finished
            }
        }

        /**
         * Takes up to CHUNK_SIZE items from the work queue.
         * Returns null when the queue is empty (all work done).
         */
        private List<HeightHash> takeChunk() throws InterruptedException {
            // Wait up to 2s for the first item
            HeightHash first = workQueue.poll(2000, TimeUnit.MILLISECONDS);
            if (first == null) return null;

            List<HeightHash> chunk = new ArrayList<>(CHUNK_SIZE);
            chunk.add(first);
            workQueue.drainTo(chunk, CHUNK_SIZE - 1);
            return chunk;
        }

        /**
         * Sends GETDATA for a chunk and collects BLOCK responses.
         * Blocks are collected entirely in memory first, then handed
         * to the DB write queue — keeping the network loop non-blocking.
         */
        private void downloadChunk(HNSPeer p,
                                   List<HeightHash> chunk) throws Exception {
            // Skip heights already completed by another peer
            List<HeightHash> needed = new ArrayList<>(chunk.size());
            for (HeightHash hh : chunk)
                if (!completed.containsKey(hh.height))
                    needed.add(hh);

            if (needed.isEmpty()) return;

            // Collect all blocks in memory first
            List<WriteTask> downloaded = new ArrayList<>(needed.size());

            List<byte[]> hashes = new ArrayList<>(needed.size());
            for (HeightHash hh : needed) hashes.add(hh.hash);

            p.syncBlocks(hashes, needed.getFirst().height, (height, block) -> {
                byte[] raw = buildRawBlock(block);
                downloaded.add(new WriteTask(height, block, raw));
            });

            // Now hand off to DB writer — non-blocking path
            for (WriteTask task : downloaded) {
                completed.put(task.height, Boolean.TRUE);
                writeQueue.put(task); // blocks only if queue is full (512 cap)
            }
        }

        /**
         * Returns any un-downloaded items from a failed chunk back to the
         * work queue so another worker can pick them up.
         */
        private void returnToQueue(List<HeightHash> chunk) {
            int returned = 0;
            for (HeightHash hh : chunk) {
                if (!completed.containsKey(hh.height)) {
                    try {
                        workQueue.put(hh);
                        returned++;
                    } catch (InterruptedException ignored) {}
                }
            }
            if (returned > 0)
                System.out.println("[" + peer.seed.ipAddress()
                        + "] Returned " + returned
                        + " blocks to queue for other peers.");
        }
    }

    // -------------------------------------------------------------------------
    // Database writer — single thread, serialises all DB writes
    // -------------------------------------------------------------------------

    private void runDatabaseWriter() {
        int compactCounter = 0;
        try {
            while (true) {
                WriteTask task = writeQueue.poll(WRITER_POLL_MS,
                        TimeUnit.MILLISECONDS);
                if (task == null) continue;
                if (task == WriteTask.POISON) break;

                try {
                    db.insertBlock(task.height, task.block, task.raw);
                    int count = writtenCount.incrementAndGet();
                    if (count % 1000 == 0)
                        System.out.printf("[DB writer] %d / %d blocks written%n",
                                count, totalBlocks);

                    // Compact every 5000 blocks to reclaim MVStore free pages
                    // MVStore accumulates stale pages during bulk writes;
                    // compaction keeps the file size proportional to live data.
                    if (++compactCounter >= 5000) {
                        compactCounter = 0;
                        db.compact();
                    }
                } catch (Exception e) {
                    System.out.println("[DB writer] Fatal error at height "
                            + task.height + ": " + e.getMessage());
                    fatalError.set(true);
                    return;
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // -------------------------------------------------------------------------
    // Progress reporter
    // -------------------------------------------------------------------------

    private void runProgressReporter() {
        try {
            while (!Thread.currentThread().isInterrupted()) {
                TimeUnit.SECONDS.sleep(30);
                int written  = writtenCount.get();
                int queued   = workQueue.size();
                int inFlight = totalBlocks - written - queued;
                // Only show progress for larger syncs — not for 1-2 block updates
                if (totalBlocks > 10)
                    System.out.printf("[Progress] Written: %d  In-flight: %d  "
                                    + "Queued: %d  Total: %d  (%.1f%%)%n",
                            written, inFlight, queued, totalBlocks,
                            100.0 * written / totalBlocks);
            }
        } catch (InterruptedException ignored) {}
    }

    // -------------------------------------------------------------------------
    // buildRawBlock — reassemble wire bytes from parsed HNSBlock
    // -------------------------------------------------------------------------

    private static byte[] buildRawBlock(HNSBlock block) {
        byte[] txCountVarint = HNSPeer.encodeVarint(block.txs.size());
        int totalSize = HNSPeer.HEADER_SIZE + txCountVarint.length;
        for (HNSBlock.Tx tx : block.txs)
            totalSize += tx.raw.length;

        byte[] raw = new byte[totalSize];
        int pos = 0;
        System.arraycopy(block.header, 0, raw, pos, HNSPeer.HEADER_SIZE);
        pos += HNSPeer.HEADER_SIZE;
        System.arraycopy(txCountVarint, 0, raw, pos, txCountVarint.length);
        pos += txCountVarint.length;
        for (HNSBlock.Tx tx : block.txs) {
            System.arraycopy(tx.raw, 0, raw, pos, tx.raw.length);
            pos += tx.raw.length;
        }
        return raw;
    }

    // -------------------------------------------------------------------------
    // Inner types
    // -------------------------------------------------------------------------

    /** A (height, hash) pair representing one block of work. */
    private static class HeightHash {
        final int    height;
        final byte[] hash;
        HeightHash(int height, byte[] hash) {
            this.height = height;
            this.hash   = hash;
        }
    }

    /** A completed block ready for database insertion. */
    private static class WriteTask {
        static final WriteTask POISON = new WriteTask(-1, null, null);
        final int      height;
        final HNSBlock block;
        final byte[]   raw;
        WriteTask(int height, HNSBlock block, byte[] raw) {
            this.height = height;
            this.block  = block;
            this.raw    = raw;
        }
    }
}