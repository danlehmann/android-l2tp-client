package net.daniellehmann.l2tpvpn.core;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A pair of ESP security associations (inbound + outbound) in UDP-encapsulated
 * transport mode. Packets produced here are sent as-is on UDP port 4500.
 */
public final class ChildSa {
    public final int spiIn;
    public final int spiOut;
    public final Crypto.Enc enc;
    public final Crypto.Integ integ;
    public final long createdAt = System.currentTimeMillis();
    public final IkeSession owner;

    private final SecretKeySpec encKeyIn, encKeyOut, authKeyIn, authKeyOut;
    private final Object outLock = new Object();
    private final Object inLock = new Object();
    private Cipher outCipher, inCipher;
    private Mac outMac, inMac;
    private long seqOut;
    private long replayTop;     // highest sequence number accepted
    private long replayBitmap;  // bit i set => replayTop - i seen
    public volatile long lastInbound = System.currentTimeMillis();
    public volatile long bytesIn, bytesOut;

    ChildSa(IkeSession owner, int spiIn, int spiOut, Crypto.Enc enc, Crypto.Integ integ,
            byte[] keymatIn, byte[] keymatOut) {
        this.owner = owner;
        this.spiIn = spiIn;
        this.spiOut = spiOut;
        this.enc = enc;
        this.integ = integ;
        String cipherAlg = enc == Crypto.TDES ? "DESede" : "AES";
        encKeyIn = new SecretKeySpec(keymatIn, 0, enc.keyBytes, cipherAlg);
        encKeyOut = new SecretKeySpec(keymatOut, 0, enc.keyBytes, cipherAlg);
        authKeyIn = new SecretKeySpec(keymatIn, enc.keyBytes, integ.keyBytes, integ.mac);
        authKeyOut = new SecretKeySpec(keymatOut, enc.keyBytes, integ.keyBytes, integ.mac);
        try {
            String t = cipherAlg + "/CBC/NoPadding";
            outCipher = Cipher.getInstance(t);
            inCipher = Cipher.getInstance(t);
            outMac = Mac.getInstance(integ.mac);
            inMac = Mac.getInstance(integ.mac);
            outMac.init(authKeyOut);
            inMac.init(authKeyIn);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public int overhead() {
        // SPI + seq + IV + max padding + pad len + next header + ICV
        return 8 + enc.block + (enc.block - 1) + 2 + integ.icvLen;
    }

    /** Wraps {@code payload} (an upper-layer packet, e.g. UDP header + L2TP) into ESP. */
    public byte[] encrypt(byte[] payload, int off, int len, int nextHeader) {
        int bs = Math.max(enc.block, 4);
        int plainLen = ((len + 2 + bs - 1) / bs) * bs;
        int padLen = plainLen - len - 2;
        byte[] plain = new byte[plainLen];
        System.arraycopy(payload, off, plain, 0, len);
        for (int i = 0; i < padLen; i++) plain[len + i] = (byte) (i + 1);
        plain[plainLen - 2] = (byte) padLen;
        plain[plainLen - 1] = (byte) nextHeader;

        byte[] iv = Bytes.random(enc.block);
        int hdr = 8 + iv.length;
        byte[] out = new byte[hdr + plainLen + integ.icvLen];
        synchronized (outLock) {
            seqOut++;
            if (seqOut > 0xffffffffL) throw new IllegalStateException("ESP sequence exhausted");
            Bytes.put32(out, 0, spiOut);
            Bytes.put32(out, 4, (int) seqOut);
            System.arraycopy(iv, 0, out, 8, iv.length);
            try {
                outCipher.init(Cipher.ENCRYPT_MODE, encKeyOut, new IvParameterSpec(iv));
                outCipher.doFinal(plain, 0, plainLen, out, hdr);
                outMac.update(out, 0, hdr + plainLen);
                byte[] icv = outMac.doFinal();
                System.arraycopy(icv, 0, out, hdr + plainLen, integ.icvLen);
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
        }
        bytesOut += len;
        return out;
    }

    public long sequenceOut() {
        synchronized (outLock) {
            return seqOut;
        }
    }

    /** Result of a successful decryption. */
    public static final class Plain {
        public byte[] data;
        public int len;
        public int nextHeader;
    }

    /**
     * Authenticates and decrypts an ESP packet addressed to {@link #spiIn}.
     * Returns null for replays, bad ICVs, or malformed packets.
     */
    public Plain decrypt(byte[] pkt, int off, int len) {
        int ivLen = enc.block;
        int ctLen = len - 8 - ivLen - integ.icvLen;
        if (ctLen < enc.block || ctLen % enc.block != 0) return null;
        long seq = Bytes.u32(pkt, off + 4) & 0xffffffffL;
        synchronized (inLock) {
            if (!replayOk(seq)) return null;
            try {
                inMac.update(pkt, off, len - integ.icvLen);
                byte[] icv = inMac.doFinal();
                if (!Bytes.equal(icv, 0, pkt, off + len - integ.icvLen, integ.icvLen)) return null;
                inCipher.init(Cipher.DECRYPT_MODE, encKeyIn, new IvParameterSpec(pkt, off + 8, ivLen));
                byte[] plain = inCipher.doFinal(pkt, off + 8 + ivLen, ctLen);
                int padLen = plain[ctLen - 2] & 0xff;
                int dataLen = ctLen - 2 - padLen;
                if (dataLen < 0) return null;
                replayUpdate(seq);
                Plain p = new Plain();
                p.data = plain;
                p.len = dataLen;
                p.nextHeader = plain[ctLen - 1] & 0xff;
                lastInbound = System.currentTimeMillis();
                bytesIn += dataLen;
                return p;
            } catch (GeneralSecurityException e) {
                return null;
            }
        }
    }

    private boolean replayOk(long seq) {
        if (seq == 0) return false;
        if (seq > replayTop) return true;
        long diff = replayTop - seq;
        if (diff >= 64) return false;
        return (replayBitmap & (1L << diff)) == 0;
    }

    private void replayUpdate(long seq) {
        if (seq > replayTop) {
            long shift = seq - replayTop;
            replayBitmap = shift >= 64 ? 1 : (replayBitmap << shift) | 1;
            replayTop = seq;
        } else {
            replayBitmap |= 1L << (replayTop - seq);
        }
    }

    @Override
    public String toString() {
        return String.format("ESP %s/%s in=%08x out=%08x", enc, integ, spiIn, spiOut);
    }
}
