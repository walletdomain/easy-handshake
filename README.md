# Handshake Java Node

A full [Handshake (HNS)](https://handshake.org) blockchain node implemented in Java.

Built from scratch as a complete reimplementation of [hsd](https://github.com/handshake-org/hsd),
the reference Handshake node written in Node.js. This implementation:

- Syncs the full Handshake blockchain via the native P2P brontide protocol
- Serves blocks to other peers (acts as a full peer node)
- Stores the chain using H2 MVStore with LZ4 compression (~40 GB for full chain)
- Implements the complete brontide Noise XK handshake (both initiator and responder)
- Supports key rotation every 1000 messages matching hsd's implementation

## Features

- **Full chain sync** — downloads all block headers and raw blocks from multiple peers in parallel (torrent-style)
- **Brontide encrypted transport** — all P2P communication is authenticated and encrypted using the Handshake brontide protocol (Noise XK with secp256k1 + Elligator Squared encoding)
- **Parallel block download** — 7 peers download simultaneously with automatic work redistribution if a peer drops
- **UTXO set** — maintains the full unspent transaction output set, deleting spent outputs
- **Peer server** — accepts inbound brontide connections and serves `GETDATA`, `GETHEADERS`, and `PING` requests
- **Persistent node identity** — generates a permanent secp256k1 keypair on first run; stable brontide address across restarts
- **Gap-safe resume** — if sync is interrupted, resumes from the highest contiguous block without skipping gaps
- **Key rotation** — implements hsd's ChaCha20-Poly1305 key rotation every 1000 messages

## Requirements

- Java 21 or higher
- ~50 GB disk space for the full chain database
- Port 44806 open for inbound peer connections (TCP)

## Building

```bash
git clone https://github.com/walletdomain/easy-handshake.git
cd easy-handshake
mvn package
```

This produces `target/easy-handshake.jar` — a self-contained fat JAR with H2 bundled.

## Running

```bash
java -Xmx512m -jar target/easy-handshake.jar
```

On first run, the node will:
1. Generate a permanent node identity key at `~/.easy_handshake/node.key`
2. Sync all block headers from the Handshake network (~2 minutes)
3. Download all blocks in parallel from 7 seed peers (~8-12 hours on first run)
4. Start listening for inbound peer connections on port 44806

On subsequent runs (already synced), startup takes a few seconds and goes straight to listening.

## Data Directory

All data is stored in the **same directory as the JAR file** (the working directory),
making the node fully portable — it can run from a USB drive on any OS with Java 21:

```
easy-handshake/          ← run java -jar from here
├── easy-handshake.jar
├── node.key             — permanent node identity (back this up)
├── chain.mv.db          — blockchain database (~41 GB for full chain)
├── node.mv.db           — node state (future)
└── wallet.mv.db         — wallet (future)
```

To run from a USB drive:
```bash
cd /path/to/usb/easy-handshake
java -Xmx512m -jar easy-handshake.jar
```

## Architecture

```
HNSPeerManager          — main entry point, orchestrates sync phases
├── syncHeaderPhase     — sequential header sync from best peer
├── syncBlockPhase      — parallel block sync via BlockSyncCoordinator
│   └── BlockSyncCoordinator — torrent-style parallel downloader
│       ├── 7× PeerWorker   — one thread per peer, pulls from work queue
│       └── DatabaseWriter  — single thread serialises DB writes
└── PeerServer          — TCP server accepting inbound connections
    └── HNSPeer         — P2P session (version/verack, GETDATA, GETHEADERS)

BrontideState           — Noise XK handshake + ChaCha20-Poly1305 transport
├── Initiator side      — genActOne / recvActTwo / genActThree
└── Responder side      — recvActOne / genActTwo / recvActThree

Database (MVStore)      — key-value storage
├── headers             — Long(height) → byte[236] raw header
├── hashes              — String(hex)  → Long(height)
├── blocks              — Long(height) → byte[] raw block
├── utxo                — String(outpoint) → byte[] coin
└── meta                — tip pointers, schema version

Cryptography
├── Secp256k1           — EC arithmetic, ECDH, public key compression
├── Elligator           — SvdW z=1 map for uniform point encoding
└── CryptoUtils         — SHA-256, HKDF, ChaCha20-Poly1305, Blake2b
```

## Brontide Protocol

The Handshake network uses a modified Noise XK protocol called brontide:

- **Protocol name**: `Noise_XK_secp256k1_ChaChaPoly_SHA256+SVDW_Squared`
- **Prologue**: `hns`
- **Ephemeral key encoding**: Elligator Squared (SvdW) — encodes EC points as uniform random-looking 64-byte strings
- **Transport framing**: 4-byte LE length + 16-byte tag + body + 16-byte body tag
- **Key rotation**: every 1000 encrypt/decrypt operations, keys are rotated via HKDF

## Seed Nodes

The following mainnet seed nodes with brontide keys are hardcoded:

| IP | Port | Version |
|----|------|---------|
| 172.104.214.189 | 44806 | hsd:2.4.0 |
| 129.153.177.220 | 44806 | hsd:8.0.0 |
| 159.69.46.23 | 44806 | hsd:7.0.0 |
| 194.50.5.26 | 44806 | hsd:8.0.0 |
| 194.50.5.27 | 44806 | hsd:8.0.0 |
| 194.50.5.28 | 44806 | hsd:8.0.0 |
| 35.154.209.88 | 44806 | hsd:6.1.1 |

## Network Constants

| Constant | Value |
|----------|-------|
| Magic | `0x5B6EF2D3` |
| Mainnet P2P port | 12038 |
| Brontide port | 44806 |
| Genesis hash | `5b6ef2d3...` |
| Max block size | 8,000,000 bytes |
| Block header size | 236 bytes |

## Project Status

| Feature | Status |
|---------|--------|
| Brontide handshake (initiator) | ✅ Complete |
| Brontide handshake (responder) | ✅ Complete |
| Header sync | ✅ Complete |
| Parallel block sync | ✅ Complete |
| Block validation (hash check) | ✅ Complete |
| UTXO set maintenance | ✅ Complete |
| Peer server (serve blocks) | ✅ Complete |
| Persistent node identity | ✅ Complete |
| Recursive DNS resolver (.hns) | 🔲 Planned |
| Wallet | 🔲 Planned |
| Mempool | 🔲 Planned |
| Mining / Stratum server | 🔲 Planned |
| Name auction support | 🔲 Planned |

## License

MIT
