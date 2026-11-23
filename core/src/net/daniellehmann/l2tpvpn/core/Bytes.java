package net.daniellehmann.l2tpvpn.core;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.Arrays;

/** Small byte helpers shared by all protocol layers. */
public final class Bytes {
    private Bytes() {}

    public static final SecureRandom RNG = new SecureRandom();

    public static byte[] random(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    public static int u8(byte[] b, int off) {
        return b[off] & 0xff;
    }

    public static int u16(byte[] b, int off) {
        return ((b[off] & 0xff) << 8) | (b[off + 1] & 0xff);
    }

    public static int u32(byte[] b, int off) {
        return ((b[off] & 0xff) << 24) | ((b[off + 1] & 0xff) << 16)
                | ((b[off + 2] & 0xff) << 8) | (b[off + 3] & 0xff);
    }

    public static void put16(byte[] b, int off, int v) {
        b[off] = (byte) (v >>> 8);
        b[off + 1] = (byte) v;
    }

    public static void put32(byte[] b, int off, int v) {
        b[off] = (byte) (v >>> 24);
        b[off + 1] = (byte) (v >>> 16);
        b[off + 2] = (byte) (v >>> 8);
        b[off + 3] = (byte) v;
    }

    public static byte[] be32(int v) {
        byte[] b = new byte[4];
        put32(b, 0, v);
        return b;
    }

    public static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, o, p.length);
            o += p.length;
        }
        return out;
    }

    public static byte[] slice(byte[] b, int off, int len) {
        return Arrays.copyOfRange(b, off, off + len);
    }

    public static String hex(byte[] b) {
        return hex(b, 0, b.length);
    }

    public static String hex(byte[] b, int off, int len) {
        StringBuilder sb = new StringBuilder(len * 2);
        for (int i = off; i < off + len; i++) sb.append(String.format("%02x", b[i] & 0xff));
        return sb.toString();
    }

    public static byte[] unhex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    /** Constant-time comparison for MACs and authenticator values. */
    public static boolean equal(byte[] a, int aOff, byte[] b, int bOff, int len) {
        if (aOff + len > a.length || bOff + len > b.length) return false;
        int d = 0;
        for (int i = 0; i < len; i++) d |= a[aOff + i] ^ b[bOff + i];
        return d == 0;
    }

    public static String ip(byte[] a) {
        return (a[0] & 0xff) + "." + (a[1] & 0xff) + "." + (a[2] & 0xff) + "." + (a[3] & 0xff);
    }

    /** Growable big-endian writer. */
    public static final class Writer {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        public Writer u8(int v) {
            out.write(v);
            return this;
        }

        public Writer u16(int v) {
            out.write(v >>> 8);
            out.write(v);
            return this;
        }

        public Writer u32(int v) {
            u16(v >>> 16);
            return u16(v);
        }

        public Writer bytes(byte[] b) {
            out.write(b, 0, b.length);
            return this;
        }

        public Writer bytes(byte[] b, int off, int len) {
            out.write(b, off, len);
            return this;
        }

        public int size() {
            return out.size();
        }

        public byte[] toByteArray() {
            return out.toByteArray();
        }
    }
}
