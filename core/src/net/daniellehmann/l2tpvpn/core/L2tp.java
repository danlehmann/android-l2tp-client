package net.daniellehmann.l2tpvpn.core;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.concurrent.ScheduledFuture;

/**
 * L2TPv2 (RFC 2661) LAC side: one control connection carrying one incoming call
 * whose payload is PPP. Control messages are delivered reliably (Ns/Nr with
 * retransmission); data messages carry PPP frames.
 *
 * Control-path methods run on the engine's control thread; {@link #parseData}
 * is stateless apart from volatile ids so the receive thread can use it.
 */
public final class L2tp {
    public interface Host {
        void sendL2tp(byte[] packet);
        ScheduledFuture<?> schedule(Runnable r, long delayMs);
        void log(String msg);
        void onL2tpSessionUp();
        void onL2tpFailed(String reason);
    }

    private static final int SCCRQ = 1, SCCRP = 2, SCCCN = 3, STOPCCN = 4, HELLO = 6;
    private static final int ICRQ = 10, ICRP = 11, ICCN = 12, CDN = 14, WEN = 15, SLI = 16;
    private static final long[] RETRANSMIT_MS = {1000, 2000, 4000, 8000, 8000, 8000};
    private static final long HELLO_MS = 60000;

    private final Host host;
    private final String hostName;
    public final int localTunnelId = 1 + Bytes.RNG.nextInt(0xfffe);
    public final int localSessionId = 1 + Bytes.RNG.nextInt(0xfffe);
    public volatile int peerTunnelId;
    public volatile int peerSessionId;

    private int ns;  // next sequence number we send
    private int nr;  // next sequence number we expect
    private final ArrayDeque<Outgoing> queue = new ArrayDeque<>();
    private ScheduledFuture<?> retxTimer;
    private ScheduledFuture<?> helloTimer;
    private int attempt;
    private boolean sessionUp;
    private boolean closed;
    private boolean sentSomething;

    private static final class Outgoing {
        final int ns;
        final int session;
        final byte[] avps;
        Outgoing(int ns, int session, byte[] avps) { this.ns = ns; this.session = session; this.avps = avps; }
    }

    public L2tp(Host host, String hostName) {
        this.host = host;
        this.hostName = hostName;
    }

    // ------------------------------------------------------------------ AVPs

    private static void avp(Bytes.Writer w, boolean mandatory, int type, byte[] value) {
        w.u16((mandatory ? 0x8000 : 0) | (6 + value.length)).u16(0).u16(type).bytes(value);
    }

    private static void avp16(Bytes.Writer w, int type, int v) {
        avp(w, true, type, new byte[] {(byte) (v >>> 8), (byte) v});
    }

    private static void avp32(Bytes.Writer w, int type, int v) {
        avp(w, true, type, Bytes.be32(v));
    }

    private static Bytes.Writer msg(int type) {
        Bytes.Writer w = new Bytes.Writer();
        avp16(w, 0, type);
        return w;
    }

    // ------------------------------------------------------------------ lifecycle

    public void start() {
        Bytes.Writer w = msg(SCCRQ);
        avp16(w, 2, 0x0100);                       // protocol version 1.0
        avp32(w, 3, 3);                            // framing capabilities: sync + async
        avp32(w, 4, 0);                            // bearer capabilities
        avp(w, false, 6, new byte[] {0x01, 0x00}); // firmware revision
        avp(w, true, 7, hostName.getBytes(StandardCharsets.US_ASCII));
        avp(w, false, 8, "l2tpvpn".getBytes(StandardCharsets.US_ASCII));
        avp16(w, 9, localTunnelId);
        avp16(w, 10, 8);                           // receive window size
        log("sending SCCRQ (tunnel " + localTunnelId + ")");
        enqueue(w.toByteArray());
    }

    /** Best-effort teardown: one unacknowledged StopCCN. */
    public void stop() {
        if (closed) return;
        closed = true;
        cancelTimers();
        if (peerTunnelId != 0) {
            Bytes.Writer w = msg(STOPCCN);
            avp(w, true, 1, new byte[] {0, 1});  // result: general request to clear
            avp16(w, 9, localTunnelId);
            host.sendL2tp(controlPacket(ns, 0, w.toByteArray()));
        }
    }

    private void log(String s) {
        host.log("L2TP: " + s);
    }

    private void fail(String reason) {
        if (closed) return;
        closed = true;
        cancelTimers();
        log("failed: " + reason);
        host.onL2tpFailed(reason);
    }

    private void cancelTimers() {
        if (retxTimer != null) retxTimer.cancel(false);
        if (helloTimer != null) helloTimer.cancel(false);
    }

    // ------------------------------------------------------------------ reliable delivery

    private byte[] controlPacket(int seq, int session, byte[] avps) {
        byte[] p = new byte[12 + avps.length];
        Bytes.put16(p, 0, 0xc802);  // T, L, S, version 2
        Bytes.put16(p, 2, p.length);
        Bytes.put16(p, 4, peerTunnelId);
        Bytes.put16(p, 6, session);
        Bytes.put16(p, 8, seq);
        Bytes.put16(p, 10, nr);
        System.arraycopy(avps, 0, p, 12, avps.length);
        return p;
    }

    private void enqueue(byte[] avps) {
        enqueue(0, avps);
    }

    /** Queues a control message; session-scoped messages carry the peer's session id. */
    private void enqueue(int session, byte[] avps) {
        queue.add(new Outgoing(ns, session, avps));
        ns = (ns + 1) & 0xffff;
        if (queue.size() == 1) transmitHead(true);
    }

    private void transmitHead(boolean fresh) {
        Outgoing o = queue.peek();
        if (o == null) return;
        if (fresh) attempt = 0;
        sentSomething = true;
        host.sendL2tp(controlPacket(o.ns, o.session, o.avps));
        if (retxTimer != null) retxTimer.cancel(false);
        retxTimer = host.schedule(() -> {
            if (closed || queue.peek() != o) return;
            if (attempt >= RETRANSMIT_MS.length) {
                fail("no acknowledgement from server (control channel timed out)");
                return;
            }
            attempt++;
            transmitHead(false);
        }, RETRANSMIT_MS[Math.min(attempt, RETRANSMIT_MS.length - 1)]);
    }

    private void processAck(int peerNr) {
        boolean popped = false;
        while (!queue.isEmpty()) {
            int d = (peerNr - queue.peek().ns) & 0xffff;
            if (d == 0 || d > 0x8000) break;  // head not yet acknowledged
            queue.poll();
            popped = true;
        }
        if (popped) {
            if (retxTimer != null) retxTimer.cancel(false);
            if (!queue.isEmpty()) transmitHead(true);
        }
    }

    private void sendZlb() {
        host.sendL2tp(controlPacket(ns, 0, new byte[0]));
    }

    // ------------------------------------------------------------------ receive

    /** Handles a control message (T bit set). Runs on the control thread. */
    public void onControl(byte[] p, int off, int len) {
        if (closed || len < 12) return;
        int flags = Bytes.u16(p, off);
        if ((flags & 0xc800) != 0xc800 || (flags & 0x000f) != 2) return;
        int length = Bytes.u16(p, off + 2);
        if (length < 12 || length > len) return;
        int tid = Bytes.u16(p, off + 4);
        if (tid != localTunnelId) return;
        int pns = Bytes.u16(p, off + 8);
        int pnr = Bytes.u16(p, off + 10);
        processAck(pnr);
        if (length == 12) return;  // ZLB acknowledgement only

        if (pns != nr) {
            // Duplicate (already processed) → re-acknowledge; out of order → drop.
            if (((nr - pns) & 0xffff) < 0x8000) sendZlb();
            return;
        }
        nr = (nr + 1) & 0xffff;
        sentSomething = false;
        try {
            handleMessage(p, off + 12, off + length);
        } catch (ProtocolException e) {
            fail(e.getMessage());
            return;
        }
        if (!sentSomething && !closed) sendZlb();
    }

    private void handleMessage(byte[] p, int start, int end) throws ProtocolException {
        int type = -1;
        int assignedTunnel = -1, assignedSession = -1;
        int resultCode = -1, errorCode = -1;
        String resultMsg = "";
        boolean challenge = false;
        int o = start;
        while (o + 6 <= end) {
            int fl = Bytes.u16(p, o);
            int alen = fl & 0x3ff;
            if (alen < 6 || o + alen > end) throw new ProtocolException("bad AVP length");
            int vendor = Bytes.u16(p, o + 2);
            int at = Bytes.u16(p, o + 4);
            int vo = o + 6, vl = alen - 6;
            boolean mandatory = (fl & 0x8000) != 0;
            if ((fl & 0x4000) != 0) {
                throw new ProtocolException("server uses hidden AVPs (L2TP tunnel secret), which is not supported");
            }
            if (vendor == 0) {
                switch (at) {
                    case 0: if (vl >= 2) type = Bytes.u16(p, vo); break;
                    case 1:
                        if (vl >= 2) resultCode = Bytes.u16(p, vo);
                        if (vl >= 4) errorCode = Bytes.u16(p, vo + 2);
                        if (vl > 4) resultMsg = new String(p, vo + 4, vl - 4, StandardCharsets.UTF_8);
                        break;
                    case 9: if (vl >= 2) assignedTunnel = Bytes.u16(p, vo); break;
                    case 11: challenge = true; break;
                    case 14: if (vl >= 2) assignedSession = Bytes.u16(p, vo); break;
                    default: break;
                }
            } else if (mandatory && type != HELLO) {
                log("ignoring unknown mandatory vendor AVP " + vendor + ":" + at);
            }
            o += alen;
        }

        switch (type) {
            case SCCRP: {
                if (assignedTunnel <= 0) throw new ProtocolException("SCCRP without Assigned Tunnel ID");
                if (challenge) {
                    throw new ProtocolException("server requires L2TP tunnel authentication (secret), which is not supported");
                }
                peerTunnelId = assignedTunnel;
                log("tunnel up (peer tunnel " + peerTunnelId + "), opening session");
                enqueue(msg(SCCCN).toByteArray());
                Bytes.Writer w = msg(ICRQ);
                avp16(w, 14, localSessionId);
                avp32(w, 15, Bytes.RNG.nextInt() & 0x7fffffff);  // call serial number
                enqueue(w.toByteArray());
                scheduleHello();
                break;
            }
            case ICRP: {
                if (assignedSession <= 0) throw new ProtocolException("ICRP without Assigned Session ID");
                peerSessionId = assignedSession;
                Bytes.Writer w = msg(ICCN);
                avp32(w, 24, 100000000);  // TX connect speed
                avp32(w, 19, 1);          // framing type: synchronous
                enqueue(peerSessionId, w.toByteArray());
                sessionUp = true;
                log("session up (peer session " + peerSessionId + ")");
                host.onL2tpSessionUp();
                break;
            }
            case STOPCCN:
                throw new ProtocolException("server closed the tunnel" + describeResult(resultCode, errorCode, resultMsg));
            case CDN:
                throw new ProtocolException("server disconnected the call" + describeResult(resultCode, errorCode, resultMsg));
            case HELLO:
            case WEN:
            case SLI:
                break;
            default:
                log("ignoring control message type " + type);
                break;
        }
    }

    private static String describeResult(int result, int error, String msg) {
        if (result < 0) return "";
        return " (result " + result + (error > 0 ? ", error " + error : "")
                + (msg.isEmpty() ? "" : ": " + msg.trim()) + ")";
    }

    private void scheduleHello() {
        helloTimer = host.schedule(() -> {
            if (closed) return;
            if (queue.isEmpty()) enqueue(msg(HELLO).toByteArray());
            scheduleHello();
        }, HELLO_MS);
    }

    public boolean isSessionUp() {
        return sessionUp && !closed;
    }

    // ------------------------------------------------------------------ data

    /** Header for data messages: no length, no sequence numbers. */
    public int writeDataHeader(byte[] buf, int off) {
        Bytes.put16(buf, off, 0x0002);
        Bytes.put16(buf, off + 2, peerTunnelId);
        Bytes.put16(buf, off + 4, peerSessionId);
        return 6;
    }

    public static final int DATA_HDR_LEN = 6;

    /**
     * Locates the PPP frame inside an L2TP data message. Returns the payload
     * offset, or -1 if this is not a data message for our session. Control
     * messages return -2.
     */
    public int parseData(byte[] p, int off, int len) {
        if (len < 6) return -1;
        int flags = Bytes.u16(p, off);
        if ((flags & 0x000f) != 2) return -1;
        if ((flags & 0x8000) != 0) return -2;
        int o = off + 2;
        if ((flags & 0x4000) != 0) o += 2;
        if (o + 4 > off + len) return -1;
        int tid = Bytes.u16(p, o);
        int sid = Bytes.u16(p, o + 2);
        if (tid != localTunnelId || sid != localSessionId) return -1;
        o += 4;
        if ((flags & 0x0800) != 0) o += 4;
        if ((flags & 0x0200) != 0) {
            if (o + 2 > off + len) return -1;
            o += 2 + Bytes.u16(p, o);
        }
        return o <= off + len ? o : -1;
    }
}
