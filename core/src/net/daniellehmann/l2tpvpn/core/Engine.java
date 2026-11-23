package net.daniellehmann.l2tpvpn.core;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Drives one VPN connection: IKEv1 → ESP-in-UDP → L2TP → PPP → TUN.
 *
 * Threads: a single control thread owns all protocol state machines; a receive
 * thread decrypts ESP and writes IP packets straight to the TUN; a TUN thread
 * encrypts outgoing packets. Only immutable/volatile state is shared.
 *
 * Robustness rules:
 *  - Any failure that is not a credentials problem is retried with backoff.
 *  - The TUN interface stays up while reconnecting, so traffic is blocked
 *    rather than leaking outside the tunnel.
 *  - IKE and ESP are re-established make-before-break on a timer, and server
 *    initiated rekeys and deletes are honoured.
 */
public final class Engine {
    public enum State { DISCONNECTED, CONNECTING, CONNECTED, RECONNECTING, WAITING_FOR_NETWORK, FAILED }

    private static final int IKE_PORT = 500;
    private static final int NATT_PORT = 4500;
    private static final int L2TP_PORT = 1701;
    private static final long ATTEMPT_TIMEOUT_MS = 45000;
    private static final long KEEPALIVE_MS = 20000;
    private static final long[] BACKOFF_MS = {1000, 2000, 4000, 8000, 15000, 30000};
    private static final int OUT_HDR = 8 + L2tp.DATA_HDR_LEN + 4;  // UDP + L2TP + PPP(ff03 + proto)

    private final Config cfg;
    private final Platform platform;
    private final ScheduledThreadPoolExecutor exec = new ScheduledThreadPoolExecutor(1, r -> {
        Thread t = new Thread(r, "l2tp-control");
        t.setDaemon(true);
        return t;
    });

    // Control-thread state
    private State state = State.DISCONNECTED;
    private boolean stopped;
    private int ikeSerial;
    private int failures;
    private boolean qmPfs;
    private boolean qmIds = true;
    private InetAddress server;
    private byte[] serverIp;
    private byte[] localIp;
    private IkeSession ike;
    private IkeSession rekeyIke;
    private final List<IkeSession> retiring = new ArrayList<>();
    private L2tp l2tp;
    private Ppp ppp;
    private Platform.TunSettings tunSettings;
    private ScheduledFuture<?> attemptTimer, retryTimer, rekeyTimer, keepaliveTimer;
    private boolean networkAvailable = true;
    private String lastError = "";

    // Shared with the I/O threads
    private volatile DatagramSocket socket;
    private volatile ChildSa outSa;
    private volatile ChildSa[] inSas = new ChildSa[0];
    private volatile L2tp dataL2tp;
    private volatile Ppp dataPpp;
    private volatile Platform.Tun tun;
    private volatile long lastTx;
    private volatile long retiredIn, retiredOut;  // traffic of SAs already replaced
    private Thread rxThread, tunThread;

    public Engine(Config cfg, Platform platform) {
        this.cfg = cfg;
        this.platform = platform;
        exec.setRemoveOnCancelPolicy(true);
    }

    // ================================================================== public API (any thread)

    public void start() {
        exec.execute(() -> beginAttempt("connecting"));
    }

    public void stop() {
        try {
            exec.submit(() -> {
                stopped = true;
                teardownSession(true);
                closeTun();
                if (state != State.FAILED) setState(State.DISCONNECTED, "");
            }).get(5, TimeUnit.SECONDS);
        } catch (Exception e) {
            platform.log("stop: " + e);
        }
        exec.shutdownNow();
    }

    /** The underlying network changed (new default network, or lost/regained). */
    public void onNetworkChanged(boolean available) {
        exec.execute(() -> {
            if (stopped || state == State.FAILED) return;
            networkAvailable = available;
            if (!available) {
                log("underlying network lost; waiting");
                teardownSession(false);
                cancel(retryTimer);
                setState(State.WAITING_FOR_NETWORK, "");
            } else {
                log("underlying network changed; reconnecting");
                failures = 0;
                beginAttempt("network changed");
            }
        });
    }

    public String statistics() {
        long in = retiredIn, out = retiredOut;
        for (ChildSa c : inSas) {
            in += c.bytesIn;
            out += c.bytesOut;
        }
        return format(in) + " in, " + format(out) + " out";
    }

    private static String format(long b) {
        if (b < 10 * 1024) return b + " B";
        if (b < 10L * 1024 * 1024) return (b / 1024) + " KiB";
        return (b / (1024 * 1024)) + " MiB";
    }

    // ================================================================== control thread

    private void log(String s) {
        platform.log(s);
    }

    private void setState(State s, String detail) {
        state = s;
        platform.onStatus(s, detail);
    }

    private ScheduledFuture<?> schedule(Runnable r, long ms) {
        if (exec.isShutdown()) return null;
        return exec.schedule(() -> {
            try {
                r.run();
            } catch (RuntimeException e) {
                log("internal error: " + e);
                attemptFailed("internal error: " + e, false);
            }
        }, ms, TimeUnit.MILLISECONDS);
    }

    private void post(Runnable r) {
        if (exec.isShutdown()) return;
        try {
            exec.execute(() -> {
                try {
                    r.run();
                } catch (RuntimeException e) {
                    log("internal error: " + e);
                    attemptFailed("internal error: " + e, false);
                }
            });
        } catch (java.util.concurrent.RejectedExecutionException ignored) {
            // shutting down
        }
    }

    private static void cancel(ScheduledFuture<?> f) {
        if (f != null) f.cancel(false);
    }

    private void beginAttempt(String why) {
        if (stopped) return;
        teardownSession(true);
        cancel(retryTimer);
        if (!networkAvailable) {
            setState(State.WAITING_FOR_NETWORK, "");
            return;
        }
        boolean wasUp = tun != null;
        setState(wasUp ? State.RECONNECTING : State.CONNECTING, why);
        try {
            if (server == null || failures > 0) {
                InetAddress a = platform.resolve(cfg.server.trim());
                if (!(a instanceof Inet4Address)) throw new IOException("server has no IPv4 address");
                server = a;
                serverIp = a.getAddress();
            }
            DatagramSocket s = platform.openSocket();
            DatagramSocket probe = platform.openSocket();
            try {
                probe.connect(new InetSocketAddress(server, IKE_PORT));
                localIp = probe.getLocalAddress().getAddress();
            } finally {
                probe.close();
            }
            if (localIp.length != 4 || (localIp[0] | localIp[1] | localIp[2] | localIp[3]) == 0) {
                localIp = new byte[] {10, 0, 0, 2};
            }
            socket = s;
            startReceiver(s);
            log("connecting to " + server.getHostAddress() + " from " + Bytes.ip(localIp));
        } catch (IOException e) {
            attemptFailed("cannot reach server: " + e.getMessage(), false);
            return;
        }
        attemptTimer = schedule(() -> attemptFailed("connection attempt timed out", false), ATTEMPT_TIMEOUT_MS);
        ike = newIke(true);
        ike.start();
    }

    private IkeSession newIke(boolean initialContact) {
        return new IkeSession(ikeHost, ++ikeSerial, cfg.psk.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                localIp, serverIp, initialContact);
    }

    /** Stops protocol state and I/O except the TUN interface. */
    private void teardownSession(boolean graceful) {
        cancel(attemptTimer);
        cancel(rekeyTimer);
        cancel(keepaliveTimer);
        // Without a network the goodbye messages cannot be delivered; skip them.
        if (ppp != null && graceful) ppp.stop();
        if (l2tp != null && graceful) l2tp.stop();
        for (IkeSession s : allIkes()) s.delete();
        retiring.clear();
        ike = null;
        rekeyIke = null;
        l2tp = null;
        ppp = null;
        dataL2tp = null;
        dataPpp = null;
        outSa = null;
        setInbound(new ArrayList<>());
        DatagramSocket s = socket;
        socket = null;
        if (s != null) s.close();
        rxThread = null;
    }

    private List<IkeSession> allIkes() {
        List<IkeSession> l = new ArrayList<>(retiring);
        if (ike != null) l.add(ike);
        if (rekeyIke != null) l.add(rekeyIke);
        return l;
    }

    private void attemptFailed(String reason, boolean permanent) {
        if (stopped || state == State.FAILED) return;
        lastError = reason;
        teardownSession(true);
        if (permanent) {
            closeTun();
            log("giving up: " + reason);
            setState(State.FAILED, reason);
            return;
        }
        long delay = BACKOFF_MS[Math.min(failures, BACKOFF_MS.length - 1)];
        failures++;
        log("will retry in " + delay / 1000 + "s (" + reason + ")");
        setState(tun != null ? State.RECONNECTING : State.CONNECTING, reason);
        retryTimer = schedule(() -> beginAttempt("retrying after: " + reason), delay);
    }

    // ------------------------------------------------------------------ IKE callbacks

    private final IkeSession.Host ikeHost = new IkeSession.Host() {
        @Override public void sendIke(byte[] packet, boolean natt) {
            if (natt) {
                sendUdp(Bytes.concat(new byte[4], packet), NATT_PORT);
            } else {
                sendUdp(packet, IKE_PORT);
            }
        }

        @Override public ScheduledFuture<?> schedule(Runnable r, long delayMs) {
            return Engine.this.schedule(r, delayMs);
        }

        @Override public void log(String msg) {
            Engine.this.log(msg);
        }

        @Override public void onIkeEstablished(IkeSession s) {
            if (s == ike && l2tp == null) {
                quickMode(s, Engine.this::onFirstChild);
            } else if (s == rekeyIke) {
                quickMode(s, child -> finishRekey(s, child));
            }
        }

        @Override public void onIkeFailed(IkeSession s, String reason, boolean permanent) {
            if (s == ike) {
                attemptFailed(reason, permanent);
            } else if (s == rekeyIke) {
                rekeyIke = null;
                log("rekey failed (" + reason + "); retrying in 60s");
                rekeyTimer = Engine.this.schedule(Engine.this::rekey, 60000);
            }
        }

        @Override public void onIkeDeleted(IkeSession s) {
            if (s == ike) {
                if (state == State.CONNECTED && rekeyIke == null) {
                    log("server deleted the IKE SA; re-establishing");
                    retiring.add(s);
                    ike = null;
                    rekey();
                } else if (state != State.CONNECTED) {
                    attemptFailed("server deleted the IKE SA", false);
                }
            } else {
                retiring.remove(s);
            }
        }

        @Override public void onPeerChildSa(IkeSession s, ChildSa child) {
            addInbound(child);
            outSa = child;
        }

        @Override public void onChildDeleted(IkeSession s, int spiOut) {
            ChildSa gone = null;
            List<ChildSa> keep = new ArrayList<>();
            for (ChildSa c : inSas) {
                if (c.spiOut == spiOut) gone = c; else keep.add(c);
            }
            if (gone == null) return;
            setInbound(keep);
            if (outSa == gone) {
                outSa = keep.isEmpty() ? null : keep.get(keep.size() - 1);
                if (outSa == null && state == State.CONNECTED && rekeyIke == null) {
                    log("active ESP SA deleted by server; rekeying");
                    if (ike != null && ike.isEstablished()) {
                        quickMode(ike, c -> {
                            addInbound(c);
                            outSa = c;
                            if (ppp != null) ppp.probe();
                        });
                    } else {
                        rekey();
                    }
                }
            }
        }
    };

    private interface ChildCallback {
        void ok(ChildSa c);
    }

    /** Quick Mode with automatic fallback for PFS and ID payloads. */
    private void quickMode(IkeSession s, ChildCallback ok) {
        s.startQuickMode(qmPfs, qmIds, new IkeSession.QuickModeCallback() {
            @Override public void established(ChildSa child) {
                ok.ok(child);
            }

            @Override public void failed(String reason, int notifyType) {
                if (s.isDead()) return;
                if (notifyType == 14 && !qmPfs) {
                    log("retrying Quick Mode with PFS");
                    qmPfs = true;
                    quickMode(s, ok);
                } else if (notifyType == 18 && qmIds) {
                    log("retrying Quick Mode without ID payloads");
                    qmIds = false;
                    quickMode(s, ok);
                } else if (s == ike && state != State.CONNECTED) {
                    attemptFailed("IPsec SA negotiation failed: " + reason, notifyType == 14);
                } else {
                    log("Quick Mode failed: " + reason);
                    if (s == rekeyIke) {
                        rekeyIke = null;
                        s.delete();
                        rekeyTimer = schedule(Engine.this::rekey, 60000);
                    }
                }
            }
        });
    }

    /** Replaces the inbound SA set, folding the traffic of dropped SAs into the totals. */
    private void setInbound(List<ChildSa> keep) {
        for (ChildSa c : inSas) {
            if (!keep.contains(c)) {
                retiredIn += c.bytesIn;
                retiredOut += c.bytesOut;
            }
        }
        inSas = keep.toArray(new ChildSa[0]);
    }

    private void addInbound(ChildSa c) {
        ChildSa[] cur = inSas;
        ChildSa[] n = new ChildSa[cur.length + 1];
        System.arraycopy(cur, 0, n, 0, cur.length);
        n[cur.length] = c;
        inSas = n;
    }

    private void onFirstChild(ChildSa child) {
        addInbound(child);
        outSa = child;
        startKeepalive();
        l2tp = new L2tp(l2tpHost, "android");
        dataL2tp = l2tp;
        // The server installs its ESP SAs only after processing Quick Mode 3;
        // give it a moment so the first SCCRQ is not dropped.
        L2tp l = l2tp;
        schedule(() -> {
            if (l2tp == l) l.start();
        }, 150);
    }

    private void startKeepalive() {
        keepaliveTimer = schedule(() -> {
            if (System.currentTimeMillis() - lastTx >= KEEPALIVE_MS - 1000) {
                sendUdp(new byte[] {(byte) 0xff}, NATT_PORT);
            }
            startKeepalive();
        }, KEEPALIVE_MS);
    }

    // ------------------------------------------------------------------ rekey

    private void scheduleRekey() {
        cancel(rekeyTimer);
        rekeyTimer = schedule(this::rekey, cfg.rekeySeconds * 1000L);
    }

    private void rekey() {
        if (state != State.CONNECTED || rekeyIke != null || stopped) return;
        log("re-establishing IKE and ESP SAs (make-before-break)");
        rekeyIke = newIke(false);
        rekeyIke.start();
    }

    private void finishRekey(IkeSession s, ChildSa child) {
        if (s != rekeyIke) return;
        IkeSession old = ike;
        ChildSa[] oldChildren = inSas;
        addInbound(child);
        outSa = child;
        ike = s;
        rekeyIke = null;
        log("rekey complete: " + child);
        if (ppp != null) ppp.probe();
        if (old != null) retiring.add(old);
        // Give in-flight packets on the old SAs a moment, then retire them.
        schedule(() -> {
            List<ChildSa> keep = new ArrayList<>();
            for (ChildSa c : inSas) {
                boolean isOld = false;
                for (ChildSa o : oldChildren) if (o == c) isOld = true;
                if (isOld) {
                    if (c.owner.isEstablished()) c.owner.deleteChild(c);
                    else if (ike != null) ike.deleteChild(c);
                } else {
                    keep.add(c);
                }
            }
            setInbound(keep);
            for (IkeSession r : new ArrayList<>(retiring)) {
                r.delete();
                retiring.remove(r);
            }
        }, 10000);
        scheduleRekey();
    }

    // ------------------------------------------------------------------ L2TP / PPP callbacks

    private final L2tp.Host l2tpHost = new L2tp.Host() {
        @Override public void sendL2tp(byte[] packet) {
            sendInner(packet, 0, packet.length);
        }

        @Override public ScheduledFuture<?> schedule(Runnable r, long delayMs) {
            return Engine.this.schedule(r, delayMs);
        }

        @Override public void log(String msg) {
            Engine.this.log(msg);
        }

        @Override public void onL2tpSessionUp() {
            int mru = effectiveMtu();
            ppp = new Ppp(pppHost, cfg.username, cfg.password, mru);
            dataPpp = ppp;
            ppp.start();
        }

        @Override public void onL2tpFailed(String reason) {
            attemptFailed(reason, false);
        }
    };

    private int effectiveMtu() {
        if (cfg.mtu > 0) return cfg.mtu;
        // 1500 - IP(20) - UDP(8) - ESP worst case(8 + 16 IV + 15 pad + 2 + 16 ICV)
        //      - inner UDP(8) - L2TP(6) - PPP(4)  => 1397; round down for headroom.
        return 1380;
    }

    private final Ppp.Host pppHost = new Ppp.Host() {
        @Override public void sendPpp(int protocol, byte[] payload) {
            L2tp l = l2tp;
            if (l == null) return;
            byte[] buf = new byte[8 + L2tp.DATA_HDR_LEN + 4 + payload.length];
            int o = 8;
            o += l.writeDataHeader(buf, o);
            buf[o++] = (byte) 0xff;
            buf[o++] = 0x03;
            Bytes.put16(buf, o, protocol);
            o += 2;
            System.arraycopy(payload, 0, buf, o, payload.length);
            sendInnerPrefixed(buf, buf.length);
        }

        @Override public ScheduledFuture<?> schedule(Runnable r, long delayMs) {
            return Engine.this.schedule(r, delayMs);
        }

        @Override public void log(String msg) {
            Engine.this.log(msg);
        }

        @Override public void onPppUp(byte[] localIp, List<byte[]> dns, int peerMru) {
            onConnected(localIp, dns, peerMru);
        }

        @Override public void onPppFailed(String reason, boolean permanent) {
            attemptFailed(reason, permanent);
        }
    };

    private void onConnected(byte[] ip, List<byte[]> pushedDns, int peerMru) {
        cancel(attemptTimer);
        List<byte[]> dns = cfg.parsedDnsOverride();
        if (dns.isEmpty()) dns = pushedDns;
        int mtu = Math.min(effectiveMtu(), peerMru);
        Platform.TunSettings ts = new Platform.TunSettings(ip, dns, mtu, server.getHostAddress());
        if (tun == null || !ts.sameAs(tunSettings)) {
            try {
                Platform.Tun t = platform.establish(ts);
                if (t == null) {
                    attemptFailed("VPN permission was revoked", true);
                    return;
                }
                Platform.Tun old = tun;
                tun = t;
                tunSettings = ts;
                startTunReader(t);
                if (old != null) old.close();
            } catch (IOException | RuntimeException e) {
                attemptFailed("cannot create VPN interface: " + e.getMessage(), false);
                return;
            }
        }
        failures = 0;
        lastError = "";
        setState(State.CONNECTED, Bytes.ip(ip));
        scheduleRekey();
    }

    private void closeTun() {
        Platform.Tun t = tun;
        tun = null;
        tunSettings = null;
        if (t != null) t.close();
    }

    // ================================================================== data path

    private void sendUdp(byte[] data, int port) {
        DatagramSocket s = socket;
        InetAddress srv = server;
        if (s == null || srv == null) return;
        try {
            s.send(new DatagramPacket(data, data.length, srv, port));
            lastTx = System.currentTimeMillis();
        } catch (IOException e) {
            // Network errors surface through timeouts; keep the log quiet.
        }
    }

    /** Sends an L2TP packet (no UDP header yet) through ESP. */
    private void sendInner(byte[] l2tpPacket, int off, int len) {
        byte[] buf = new byte[8 + len];
        System.arraycopy(l2tpPacket, off, buf, 8, len);
        sendInnerPrefixed(buf, buf.length);
    }

    /** {@code buf} holds 8 spare bytes for the inner UDP header, then L2TP. */
    private void sendInnerPrefixed(byte[] buf, int len) {
        ChildSa sa = outSa;
        if (sa == null) return;
        Bytes.put16(buf, 0, L2TP_PORT);
        Bytes.put16(buf, 2, L2TP_PORT);
        Bytes.put16(buf, 4, len);
        Bytes.put16(buf, 6, 0);  // checksum optional for IPv4 UDP
        sendUdp(sa.encrypt(buf, 0, len, 17), NATT_PORT);
    }

    private void startReceiver(DatagramSocket s) {
        Thread t = new Thread(() -> receiveLoop(s), "l2tp-rx");
        t.setDaemon(true);
        rxThread = t;
        t.start();
    }

    private void receiveLoop(DatagramSocket s) {
        byte[] buf = new byte[65536];
        DatagramPacket p = new DatagramPacket(buf, buf.length);
        while (socket == s) {
            try {
                p.setLength(buf.length);
                s.receive(p);
            } catch (SocketException e) {
                return;  // closed
            } catch (IOException e) {
                continue;
            }
            InetAddress srv = server;
            if (srv == null || !srv.equals(p.getAddress())) continue;
            int len = p.getLength();
            if (p.getPort() == IKE_PORT) {
                byte[] copy = Bytes.slice(buf, 0, len);
                post(() -> routeIke(copy));
            } else if (p.getPort() == NATT_PORT) {
                if (len == 1 && buf[0] == (byte) 0xff) continue;  // keepalive
                if (len >= 4 && buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 0) {
                    byte[] copy = Bytes.slice(buf, 4, len - 4);
                    post(() -> routeIke(copy));
                } else if (len >= 8) {
                    onEsp(buf, len);
                }
            }
        }
    }

    private void routeIke(byte[] pkt) {
        if (pkt.length < IkeMessage.HDR_LEN) return;
        byte[] ic = Bytes.slice(pkt, 0, 8);
        for (IkeSession s : allIkes()) {
            if (s.matches(ic)) {
                s.onPacket(pkt);
                return;
            }
        }
    }

    private void onEsp(byte[] buf, int len) {
        int spi = Bytes.u32(buf, 0);
        ChildSa sa = null;
        for (ChildSa c : inSas) {
            if (c.spiIn == spi) {
                sa = c;
                break;
            }
        }
        if (sa == null) return;
        ChildSa.Plain pl = sa.decrypt(buf, 0, len);
        if (pl == null || pl.nextHeader != 17 || pl.len < 8) return;
        byte[] d = pl.data;
        if (Bytes.u16(d, 2) != L2TP_PORT) return;
        int l2off = 8, l2len = pl.len - 8;
        L2tp l = dataL2tp;
        if (l == null) return;
        int o = l.parseData(d, l2off, l2len);
        if (o == -2) {
            byte[] copy = Bytes.slice(d, l2off, l2len);
            post(() -> {
                if (l2tp == l) l.onControl(copy, 0, copy.length);
            });
            return;
        }
        if (o < 0) return;
        int end = l2off + l2len;
        if (o + 2 <= end && (d[o] & 0xff) == 0xff && d[o + 1] == 0x03) o += 2;
        if (o >= end) return;
        int proto;
        if ((d[o] & 1) != 0) {  // compressed protocol field
            proto = d[o] & 0xff;
            o += 1;
        } else {
            if (o + 2 > end) return;
            proto = Bytes.u16(d, o);
            o += 2;
        }
        Ppp pp = dataPpp;
        if (pp == null) return;
        if (proto == Ppp.PROTO_IP) {
            pp.noteDataReceived();
            Platform.Tun t = tun;
            if (t != null && pp.isOpen()) {
                try {
                    t.write(d, o, end - o);
                } catch (IOException ignored) {
                    // interface going away
                }
            }
        } else {
            byte[] copy = Bytes.slice(d, o, end - o);
            int pr = proto;
            post(() -> {
                if (ppp == pp) pp.onFrame(pr, copy, 0, copy.length);
            });
        }
    }

    private void startTunReader(Platform.Tun t) {
        Thread th = new Thread(() -> tunLoop(t), "l2tp-tun");
        th.setDaemon(true);
        tunThread = th;
        th.start();
    }

    private void tunLoop(Platform.Tun t) {
        byte[] buf = new byte[OUT_HDR + 65536];
        while (tun == t) {
            int n;
            try {
                n = t.read(buf, OUT_HDR, buf.length - OUT_HDR);
            } catch (IOException e) {
                if (tun == t) platform.log("tun read failed: " + e.getMessage());
                return;
            }
            if (n < 0) return;
            if (n == 0 || (buf[OUT_HDR] & 0xf0) != 0x40) continue;  // IPv4 only
            L2tp l = dataL2tp;
            Ppp pp = dataPpp;
            if (l == null || pp == null || !pp.isOpen()) continue;  // reconnecting: drop
            int o = 8;
            o += l.writeDataHeader(buf, o);
            buf[o++] = (byte) 0xff;
            buf[o++] = 0x03;
            Bytes.put16(buf, o, Ppp.PROTO_IP);
            sendInnerPrefixed(buf, OUT_HDR + n);
        }
    }
}
