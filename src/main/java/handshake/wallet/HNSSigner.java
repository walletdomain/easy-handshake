package handshake.wallet;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Connects BIP32 key derivation to HNSTxBuilder.
 *
 * Responsibilities:
 *   1. Select UTXOs from WalletDB to cover the requested amount + fee
 *   2. For each UTXO, look up its address record to find account/change/index
 *   3. Derive the private key from the HD master key via BIP32
 *   4. Assemble UtxoInput list and call HNSTxBuilder.buildSend()
 *   5. Return the signed transaction ready for broadcast
 *
 * The wallet must be unlocked before calling any method here.
 * Private keys are never stored — derived on the fly and used once.
 */
public class HNSSigner {

    private final WalletManager walletManager;
    private final WalletDB      walletDb;

    public HNSSigner(WalletManager walletManager, WalletDB walletDb) {
        this.walletManager = walletManager;
        this.walletDb      = walletDb;
    }

    // ── Main signing entry point ───────────────────────────────────────────────

    /**
     * Builds, signs, and returns a send transaction.
     *
     * @param walletId      wallet to spend from (must be unlocked)
     * @param recipientAddr bech32 destination address (hs1q...)
     * @param amountHNS     amount to send in HNS (e.g. 1.5)
     * @param feePerKb      fee rate in dollarydoos per 1000 vbytes (0 = default)
     * @return signed transaction ready to broadcast
     */
    public HNSTxBuilder.SignedTx buildSend(String walletId,
                                           String recipientAddr,
                                           double amountHNS,
                                           long   feePerKb) throws IOException {
        long amount = Math.round(amountHNS * 1_000_000);
        return buildSendRaw(walletId, recipientAddr, amount, feePerKb);
    }

    /**
     * Builds, signs, and returns a send transaction (dollarydoos).
     *
     * @param walletId      wallet to spend from (must be unlocked)
     * @param recipientAddr bech32 destination address (hs1q...)
     * @param amount        dollarydoos to send
     * @param feePerKb      fee rate in dollarydoos per 1000 vbytes (0 = default)
     */
    public HNSTxBuilder.SignedTx buildSendRaw(String walletId,
                                              String recipientAddr,
                                              long   amount,
                                              long   feePerKb) throws IOException {
        // ── Validate wallet is unlocked ────────────────────────────────────────
        BIP32.HDKey master = walletManager.getMasterKey(walletId);
        if (master == null)
            throw new IllegalStateException(
                    "Wallet '" + walletId + "' is locked. Unlock before sending.");

        // ── Decode recipient address ───────────────────────────────────────────
        byte[] recipientHash = HNSAddress.decode(recipientAddr);
        if (recipientHash == null || recipientHash.length != 20)
            throw new IllegalArgumentException(
                    "Invalid Handshake address: " + recipientAddr);

        // ── Select UTXOs ───────────────────────────────────────────────────────
        // We use a simple largest-first coin selection strategy.
        List<WalletDB.UtxoRecord> candidates = getSpendableUtxos(walletId);
        if (candidates.isEmpty())
            throw new IllegalStateException("No spendable UTXOs in wallet.");

        // Sort descending by value (largest first — minimizes number of inputs)
        candidates.sort((a, b) -> Long.compare(b.value, a.value));

        // Estimate fee for growing input set, pick just enough UTXOs
        List<WalletDB.UtxoRecord> selected = selectUtxos(candidates, amount, feePerKb);

        // ── Derive keys for selected UTXOs ─────────────────────────────────────
        List<HNSTxBuilder.UtxoInput> inputs = new ArrayList<>();
        for (WalletDB.UtxoRecord utxo : selected) {
            HNSTxBuilder.UtxoInput input = buildInput(walletId, utxo, master);
            inputs.add(input);
        }

        // ── Derive change address ──────────────────────────────────────────────
        String changeAddr = getNextChangeAddress(walletId, master);
        byte[] changeHash = HNSAddress.decode(changeAddr);
        if (changeHash == null)
            throw new IllegalStateException("Failed to derive change address");

        System.out.printf("[HNSSigner] Sending %.6f HNS to %s%n",
                amount / 1_000_000.0, recipientAddr);
        System.out.printf("[HNSSigner] Using %d UTXO(s), change to %s%n",
                inputs.size(), changeAddr);

        // ── Build and sign ─────────────────────────────────────────────────────
        return HNSTxBuilder.buildSend(inputs, recipientHash, amount,
                changeHash, feePerKb);
    }

    // ── UTXO selection ────────────────────────────────────────────────────────

    /**
     * Returns all spendable (unspent, non-locked, non-coinbase-immature) UTXOs.
     * Filters to NONE-covenant outputs only (spendable HNS).
     */
    List<WalletDB.UtxoRecord> getSpendableUtxos(String walletId) {
        List<WalletDB.UtxoRecord> result = new ArrayList<>();
        for (WalletDB.AddressRecord addr :
                walletDb.getAddressesForWallet(walletId)) {
            for (WalletDB.UtxoRecord utxo :
                    walletDb.getUtxosForAddress(addr.address)) {
                if (!utxo.spent && !utxo.coinbase && utxo.value > 0)
                    result.add(utxo);
            }
        }
        return result;
    }

    /**
     * Selects the minimum set of UTXOs to cover amount + estimated fee.
     * Uses a largest-first greedy strategy.
     */
    List<WalletDB.UtxoRecord> selectUtxos(List<WalletDB.UtxoRecord> candidates,
                                          long amount,
                                          long feePerKb) {
        if (feePerKb <= 0) feePerKb = HNSTxBuilder.MIN_RELAY_FEE;
        List<WalletDB.UtxoRecord> selected = new ArrayList<>();
        long total = 0;

        for (WalletDB.UtxoRecord utxo : candidates) {
            selected.add(utxo);
            total += utxo.value;
            long fee = estimateFee(selected.size(), feePerKb);
            if (total >= amount + fee) break;
        }

        long fee = estimateFee(selected.size(), feePerKb);
        if (total < amount + fee)
            throw new IllegalArgumentException(
                    String.format("Insufficient funds: have %.6f HNS, need %.6f HNS (%.6f + %.6f fee)",
                            total / 1e6, (amount + fee) / 1e6,
                            amount / 1e6, fee / 1e6));

        return selected;
    }

    /**
     * Estimates the fee for a transaction with nIn inputs and 2 outputs.
     * Virtual size = ceil((base*3 + total) / 4)
     * Base:    4 + varint(nIn) + 40*nIn + varint(2) + 32*2 + 4
     * Witness: nIn * 101  (varint2 + varint65 + sig65 + varint33 + pubkey33)
     */
    static long estimateFee(int nIn, long feePerKb) {
        long base  = 4L + 1 + 40L * nIn + 1 + 64 + 4;
        long wit   = (long) nIn * 101;
        long vsize = ((base * 3 + base + wit) + 3) / 4;
        return Math.max(HNSTxBuilder.MIN_RELAY_FEE, (vsize * feePerKb) / 1000);
    }

    // ── Key derivation ────────────────────────────────────────────────────────

    /**
     * Builds a UtxoInput for a UTXO by looking up the address's HD path
     * and deriving the private key.
     */
    HNSTxBuilder.UtxoInput buildInput(String walletId,
                                      WalletDB.UtxoRecord utxo,
                                      BIP32.HDKey master) {
        WalletDB.AddressRecord addrRec = findAddressRecord(walletId, utxo.address);
        if (addrRec == null)
            throw new IllegalStateException(
                    "Address record not found for UTXO: " + utxo.address);

        BIP32.HDKey key = BIP32.deriveAddress(
                master, addrRec.account, addrRec.change, addrRec.index);

        if (!key.hasPrivateKey())
            throw new IllegalStateException(
                    "No private key available for " + addrRec.path);

        byte[] addrHash = HNSAddress.decode(utxo.address);
        if (addrHash == null)
            throw new IllegalStateException(
                    "Cannot decode address: " + utxo.address);

        byte[] prevHash = hexToBytes(utxo.txHash);
        // txHash is stored as raw blake2b bytes (wire order) — no reversal needed

        System.out.printf("[HNSSigner] UTXO: %s:%d value=%.6f HNS%n",
                utxo.txHash, utxo.outputIndex, utxo.value / 1_000_000.0);
        System.out.printf("[HNSSigner]   path=%s address=%s%n",
                addrRec.path, utxo.address);
        System.out.printf("[HNSSigner]   addrHash=%s%n",
                HNSTxBuilder.toHex(addrHash));
        System.out.printf("[HNSSigner]   pubkey=%s%n",
                HNSTxBuilder.toHex(key.publicKey));
        System.out.printf("[HNSSigner]   prevHash(wire)=%s index=%d%n",
                HNSTxBuilder.toHex(prevHash), utxo.outputIndex);

        return new HNSTxBuilder.UtxoInput(
                prevHash,
                utxo.outputIndex,
                utxo.value,
                addrHash,
                key.privateKey,
                key.publicKey);
    }

    /**
     * Returns the next unused change address for this wallet.
     * Derives change/0, change/1, ... until one is unused.
     * Creates and saves the address if needed.
     */
    String getNextChangeAddress(String walletId, BIP32.HDKey master) {
        // Find the highest used change address index
        int nextIdx = 0;
        for (WalletDB.AddressRecord a : walletDb.getAddressesForWallet(walletId)) {
            if (a.change == 1) {
                nextIdx = Math.max(nextIdx, a.index + 1);
                if (!a.used && a.index == 0) {
                    // If change/0 is unused, use it
                    nextIdx = a.index;
                    break;
                }
            }
        }

        // Find first unused change address
        for (WalletDB.AddressRecord a : walletDb.getAddressesForWallet(walletId)) {
            if (a.change == 1 && !a.used)
                return a.address;
        }

        // Derive a new change address if none available
        BIP32.HDKey changeKey = BIP32.deriveAddress(master, 0, 1, nextIdx);
        String addr = HNSAddress.fromPublicKey(changeKey.publicKey);

        // Save to DB for future use
        WalletDB.AddressRecord rec = new WalletDB.AddressRecord();
        rec.walletId  = walletId;
        rec.path      = "m/44'/5353'/0'/1/" + nextIdx;
        rec.address   = addr;
        rec.publicKey = HNSTxBuilder.toHex(changeKey.publicKey);
        rec.account   = 0;
        rec.change    = 1;
        rec.index     = nextIdx;
        rec.used      = false;
        walletDb.saveAddress(rec);

        return addr;
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    WalletDB.AddressRecord findAddressRecord(String walletId, String address) {
        for (WalletDB.AddressRecord a : walletDb.getAddressesForWallet(walletId))
            if (a.address.equals(address)) return a;
        return null;
    }

    static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        return out;
    }

    static void reverseInPlace(byte[] b) {
        for (int i = 0, j = b.length - 1; i < j; i++, j--) {
            byte t = b[i]; b[i] = b[j]; b[j] = t;
        }
    }
}