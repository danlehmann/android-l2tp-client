package net.daniellehmann.l2tpvpn.core;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Desktop end-to-end test: runs the real Engine against a live server with a
 * fake TUN, then pings through the tunnel.
 *
 * Usage: Harness server psk user pass [rekeySeconds] [holdSeconds] [pingTarget...]
 */
public final class Harness {
    static volatile byte[] myIp;
    static volatile Engine.State lastState;
    static final CountDownLatch up = new CountDownLatch(1);
    static final BlockingQueue<byte[]> toTun = new LinkedBlockingQueue<>();
    static final BlockingQueue<byte[]> fromTun = new LinkedBlockingQueue<>();
    static final long t0 = System.currentTimeMillis();

    static void log(String s) {
        System.out.printf("%7.3f %s%n", (System.currentTimeMillis() - t0) / 1000.0, s);
    }

    public static void main(String[] a) throws Exception {
        Config cfg = new Config();
        cfg.server = a[0];
        cfg.psk = a[1];
        cfg.username = a[2];
        cfg.password = a[3];
        if (a.length > 4) cfg.rekeySeconds = Integer.parseInt(a[4]);
        int hold = a.length > 5 ? Integer.parseInt(a[5]) : 0;
        String[] targets = a.length > 6 ? java.util.Arrays.copyOfRange(a, 6, a.length)
                : new String[] {"192.168.42.1", "10.0.2.2", "1.1.1.1"};

        Platform p = new Platform() {
            @Override public InetAddress resolve(String host) throws IOException {
                return InetAddress.getByName(host);
            }

            @Override public DatagramSocket openSocket() throws IOException {
                return new DatagramSocket();
            }

            @Override public Tun establish(TunSettings s) {
                myIp = s.address;
                StringBuilder dns = new StringBuilder();
                for (byte[] d : s.dns) dns.append(Bytes.ip(d)).append(' ');
                log("TUN established: " + Bytes.ip(s.address) + " mtu " + s.mtu + " dns " + dns);
                return new Tun() {
                    volatile boolean closed;
                    @Override public int read(byte[] buf, int off, int len) throws IOException {
                        try {
                            byte[] pkt;
                            do {
                                pkt = toTun.poll(200, TimeUnit.MILLISECONDS);
                                if (closed) return -1;
                            } while (pkt == null);
                            System.arraycopy(pkt, 0, buf, off, pkt.length);
                            return pkt.length;
                        } catch (InterruptedException e) {
                            return -1;
                        }
                    }

                    @Override public void write(byte[] buf, int off, int len) {
                        fromTun.add(Bytes.slice(buf, off, len));
                    }

                    @Override public void close() {
                        closed = true;
                    }
                };
            }

            @Override public void log(String line) {
                Harness.log(line);
            }

            @Override public void onStatus(Engine.State state, String detail) {
                lastState = state;
                log("STATE " + state + (detail.isEmpty() ? "" : " (" + detail + ")"));
                if (state == Engine.State.CONNECTED) up.countDown();
            }
        };

        Engine e = new Engine(cfg, p);
        e.start();
        if (!up.await(60, TimeUnit.SECONDS)) {
            log("RESULT: did not connect");
            e.stop();
            System.exit(2);
        }
        Thread.sleep(Long.getLong("settle", 0));
        int failures = pingAll(targets, 1);
        long end = System.currentTimeMillis() + hold * 1000L;
        int seq = 100;
        while (System.currentTimeMillis() < end) {
            Thread.sleep(5000);
            failures += pingAll(new String[] {targets[0]}, seq++);
        }
        log("stats: " + e.statistics());
        e.stop();
        log(failures == 0 ? "RESULT: OK" : "RESULT: " + failures + " ping failures");
        System.exit(failures == 0 ? 0 : 1);
    }

    static int pingAll(String[] targets, int seq) throws Exception {
        int failures = 0;
        for (String t : targets) {
            byte[] dst = InetAddress.getByName(t).getAddress();
            boolean ok = false;
            for (int attempt = 0; attempt < 3 && !ok; attempt++) {
                fromTun.clear();
                long start = System.nanoTime();
                toTun.add(icmpEcho(myIp, dst, seq * 10 + attempt, 56));
                byte[] r;
                while ((r = fromTun.poll(3, TimeUnit.SECONDS)) != null) {
                    if (r.length >= 28 && r[9] == 1 && (r[20] & 0xff) == 0
                            && Bytes.equal(r, 12, dst, 0, 4)) {
                        ok = true;
                        log(String.format("ping %s ok %.1f ms", t, (System.nanoTime() - start) / 1e6));
                        break;
                    }
                }
            }
            if (!ok) {
                failures++;
                log("ping " + t + " FAILED (state " + lastState + ")");
            }
        }
        return failures;
    }

    static byte[] icmpEcho(byte[] src, byte[] dst, int seq, int dataLen) {
        byte[] p = new byte[20 + 8 + dataLen];
        p[0] = 0x45;
        Bytes.put16(p, 2, p.length);
        Bytes.put16(p, 4, seq);
        p[8] = 64;
        p[9] = 1;
        System.arraycopy(src, 0, p, 12, 4);
        System.arraycopy(dst, 0, p, 16, 4);
        Bytes.put16(p, 10, checksum(p, 0, 20));
        p[20] = 8;
        Bytes.put16(p, 24, 0x4242);
        Bytes.put16(p, 26, seq);
        for (int i = 0; i < dataLen; i++) p[28 + i] = (byte) i;
        Bytes.put16(p, 22, checksum(p, 20, 8 + dataLen));
        return p;
    }

    static int checksum(byte[] b, int off, int len) {
        long s = 0;
        for (int i = 0; i < len; i += 2) {
            s += ((b[off + i] & 0xff) << 8) | (i + 1 < len ? b[off + i + 1] & 0xff : 0);
        }
        while ((s >> 16) != 0) s = (s & 0xffff) + (s >> 16);
        return (int) (~s & 0xffff);
    }
}
