package net.daniellehmann.l2tpvpn.core;

/** Per-packet ESP throughput: encrypt on one SA, authenticate+decrypt on its mirror. */
public final class Bench {
    public static void main(String[] a) {
        bench(Crypto.AES256, Crypto.HMAC_SHA256_128);
        bench(Crypto.AES128, Crypto.HMAC_SHA1_96);
        bench(Crypto.TDES, Crypto.HMAC_SHA1_96);
    }

    static void bench(Crypto.Enc e, Crypto.Integ i) {
        byte[] k1 = Bytes.random(64), k2 = Bytes.random(64);
        ChildSa tx = new ChildSa(null, 1, 2, e, i, k1, k2);
        ChildSa rx = new ChildSa(null, 2, 1, e, i, k2, k1);
        byte[] pkt = Bytes.random(1400);
        int n = e == Crypto.TDES ? 5000 : 40000;
        for (int r = 0; r < 2; r++) {  // first round warms up the JIT
            long t0 = System.nanoTime();
            long bytes = 0;
            for (int k = 0; k < n; k++) {
                byte[] c = tx.encrypt(pkt, 0, pkt.length, 17);
                ChildSa.Plain p = rx.decrypt(c, 0, c.length);
                if (p == null || p.len != pkt.length) throw new AssertionError("roundtrip failed");
                bytes += pkt.length;
            }
            double s = (System.nanoTime() - t0) / 1e9;
            if (r == 1) System.out.printf("%s/%s: %.0f Mbit/s (encrypt+decrypt, 1400B packets, %.1f us/pkt)%n",
                    e, i, bytes * 8 / s / 1e6, s * 1e6 / n);
        }
    }
}
