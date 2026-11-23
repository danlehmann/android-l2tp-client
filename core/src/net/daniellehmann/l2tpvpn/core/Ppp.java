package net.daniellehmann.l2tpvpn.core;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ScheduledFuture;

/**
 * PPP client over L2TP: LCP, authentication (PAP, CHAP-MD5, MS-CHAPv2) and
 * IPCP with DNS. Runs on the engine's control thread.
 */
public final class Ppp {
    public interface Host {
        /** Sends a PPP frame (protocol field first, without address/control). */
        void sendPpp(int protocol, byte[] payload);
        ScheduledFuture<?> schedule(Runnable r, long delayMs);
        void log(String msg);
        void onPppUp(byte[] localIp, List<byte[]> dns, int peerMru);
        void onPppFailed(String reason, boolean permanent);
    }

    public static final int PROTO_IP = 0x0021;
    public static final int PROTO_IPV6 = 0x0057;
    static final int PROTO_LCP = 0xc021;
    static final int PROTO_PAP = 0xc023;
    static final int PROTO_CHAP = 0xc223;
    static final int PROTO_IPCP = 0x8021;

    private static final int CONF_REQ = 1, CONF_ACK = 2, CONF_NAK = 3, CONF_REJ = 4;
    private static final int TERM_REQ = 5, TERM_ACK = 6, CODE_REJ = 7, PROTO_REJ = 8;
    private static final int ECHO_REQ = 9, ECHO_REP = 10, DISCARD = 11;

    private static final int CHAP_MD5 = 5, CHAP_MSV2 = 0x81;
    private static final long RESTART_MS = 3000;
    private static final int MAX_CONFIGURE = 10;
    private static final long ECHO_MS = 15000;
    private static final int ECHO_FAILURES = 3;

    private enum Phase { LCP, AUTH, NETWORK, OPEN, DEAD }

    private final Host host;
    private final String username;
    private final String password;
    private final int mru;
    private final int magic = Bytes.RNG.nextInt() | 1;
    private Phase phase = Phase.LCP;
    private int nextId = Bytes.RNG.nextInt(256);

    // LCP
    private boolean lcpAckRcvd, lcpAckSent;
    private boolean sendMru = true;
    private boolean resentForPeer;
    private int lcpReqId;
    private int lcpTries;
    private ScheduledFuture<?> lcpTimer;
    private int authProto;  // 0 = none, PROTO_PAP, PROTO_CHAP
    private int chapAlg;
    private int peerMru = 1500;

    // Auth
    private ScheduledFuture<?> papTimer;
    private int papTries;
    private MsChapV2 mschap;
    private boolean authDone;

    // IPCP
    private boolean ipcpAckRcvd, ipcpAckSent, ipcpStarted;
    private byte[] reqIp = new byte[4];
    private byte[] reqDns1 = new byte[4], reqDns2 = new byte[4];
    private boolean askDns1 = true, askDns2 = true;
    private int ipcpReqId;
    private int ipcpTries;
    private ScheduledFuture<?> ipcpTimer;

    // Echo
    private ScheduledFuture<?> echoTimer;
    private int echoOutstanding;
    public volatile long lastRx = System.currentTimeMillis();

    public Ppp(Host host, String username, String password, int mru) {
        this.host = host;
        this.username = username;
        this.password = password;
        this.mru = mru;
    }

    private void log(String s) {
        host.log("PPP: " + s);
    }

    public void start() {
        sendLcpRequest();
    }

    public void stop() {
        if (phase == Phase.DEAD) return;
        if (phase == Phase.OPEN || phase == Phase.NETWORK || phase == Phase.AUTH) {
            sendCp(PROTO_LCP, TERM_REQ, id(), "user request".getBytes(StandardCharsets.US_ASCII));
        }
        die();
    }

    private void die() {
        phase = Phase.DEAD;
        for (ScheduledFuture<?> f : new ScheduledFuture<?>[] {lcpTimer, papTimer, ipcpTimer, echoTimer}) {
            if (f != null) f.cancel(false);
        }
    }

    private void fail(String reason, boolean permanent) {
        if (phase == Phase.DEAD) return;
        log("failed: " + reason);
        die();
        host.onPppFailed(reason, permanent);
    }

    private int id() {
        nextId = (nextId + 1) & 0xff;
        return nextId;
    }

    private void sendCp(int proto, int code, int id, byte[] data) {
        byte[] p = new byte[4 + data.length];
        p[0] = (byte) code;
        p[1] = (byte) id;
        Bytes.put16(p, 2, p.length);
        System.arraycopy(data, 0, p, 4, data.length);
        host.sendPpp(proto, p);
    }

    // ------------------------------------------------------------------ input

    /** Handles a non-IP PPP frame (protocol already decoded). */
    public void onFrame(int proto, byte[] p, int off, int len) {
        if (phase == Phase.DEAD) return;
        lastRx = System.currentTimeMillis();
        echoOutstanding = 0;
        if (proto == PROTO_LCP) {
            onLcp(p, off, len);
        } else if (proto == PROTO_PAP && phase == Phase.AUTH) {
            onPap(p, off, len);
        } else if (proto == PROTO_CHAP && (phase == Phase.AUTH || phase == Phase.NETWORK || phase == Phase.OPEN)) {
            onChap(p, off, len);
        } else if (proto == PROTO_IPCP && (phase == Phase.NETWORK || phase == Phase.OPEN)) {
            onIpcp(p, off, len);
        } else if (phase != Phase.LCP) {
            // Unsupported protocol (IPv6CP, CCP, ...): Protocol-Reject it.
            byte[] data = new byte[2 + Math.min(len, 64)];
            Bytes.put16(data, 0, proto);
            System.arraycopy(p, off, data, 2, data.length - 2);
            sendCp(PROTO_LCP, PROTO_REJ, id(), data);
        }
    }

    // ------------------------------------------------------------------ LCP

    private void sendLcpRequest() {
        Bytes.Writer w = new Bytes.Writer();
        if (sendMru) w.u8(1).u8(4).u16(mru);
        w.u8(5).u8(6).u32(magic);
        lcpReqId = id();
        sendCp(PROTO_LCP, CONF_REQ, lcpReqId, w.toByteArray());
        if (lcpTimer != null) lcpTimer.cancel(false);
        lcpTimer = host.schedule(() -> {
            if (phase != Phase.LCP || lcpAckRcvd) return;
            if (++lcpTries >= MAX_CONFIGURE) {
                fail("LCP negotiation timed out", false);
                return;
            }
            sendLcpRequest();
        }, RESTART_MS);
    }

    private void onLcp(byte[] p, int off, int len) {
        if (len < 4) return;
        int code = p[off] & 0xff;
        int id = p[off + 1] & 0xff;
        int plen = Math.min(Bytes.u16(p, off + 2), len);
        if (plen < 4) return;
        int dOff = off + 4, dLen = plen - 4;
        switch (code) {
            case CONF_REQ:
                if (phase != Phase.LCP) {
                    fail("server restarted link negotiation", false);
                    return;
                }
                onLcpConfReq(id, p, dOff, dLen);
                break;
            case CONF_ACK:
                if (id == lcpReqId && phase == Phase.LCP) {
                    lcpAckRcvd = true;
                    if (lcpTimer != null) lcpTimer.cancel(false);
                    maybeLcpOpen();
                }
                break;
            case CONF_NAK:
            case CONF_REJ:
                if (id != lcpReqId || phase != Phase.LCP) break;
                for (int o = dOff; o + 2 <= dOff + dLen; ) {
                    int t = p[o] & 0xff, l = p[o + 1] & 0xff;
                    if (l < 2) break;
                    if (t == 1) sendMru = false;  // let the server use the default MRU
                    if (t == 5 && code == CONF_REJ) log("server rejected magic number (continuing)");
                    o += l;
                }
                sendLcpRequest();
                break;
            case TERM_REQ:
                sendCp(PROTO_LCP, TERM_ACK, id, new byte[0]);
                fail(authDone || phase != Phase.AUTH ? "server terminated the PPP link"
                        : "server terminated the PPP link during authentication — check username/password", !authDone && phase == Phase.AUTH);
                break;
            case ECHO_REQ:
                if (phase != Phase.LCP) {
                    byte[] data = new byte[dLen];
                    System.arraycopy(p, dOff, data, 0, dLen);
                    if (dLen >= 4) Bytes.put32(data, 0, magic);
                    sendCp(PROTO_LCP, ECHO_REP, id, data);
                }
                break;
            case ECHO_REP:
                echoOutstanding = 0;
                break;
            case PROTO_REJ:
                if (dLen >= 2) log("server rejected protocol " + Integer.toHexString(Bytes.u16(p, dOff)));
                break;
            case TERM_ACK:
            case CODE_REJ:
            case DISCARD:
                break;
            default:
                byte[] rej = new byte[plen];
                System.arraycopy(p, off, rej, 0, plen);
                sendCp(PROTO_LCP, CODE_REJ, id(), rej);
        }
    }

    private void onLcpConfReq(int id, byte[] p, int off, int len) {
        // Our first Configure-Request usually races pppd startup on the server
        // and is lost; answer the server's first request by resending ours.
        if (!lcpAckRcvd && !resentForPeer) {
            resentForPeer = true;
            sendLcpRequest();
        }
        Bytes.Writer rej = new Bytes.Writer(), nak = new Bytes.Writer();
        int newAuth = 0, newAlg = 0, newMru = 1500;
        for (int o = off; o + 2 <= off + len; ) {
            int t = p[o] & 0xff, l = p[o + 1] & 0xff;
            if (l < 2 || o + l > off + len) {
                rej.bytes(p, o, off + len - o);
                break;
            }
            switch (t) {
                case 1:  // MRU
                    if (l == 4) newMru = Bytes.u16(p, o + 2);
                    break;
                case 2:  // ACCM (meaningless on a synchronous link)
                case 5:  // magic number
                case 7:  // PFC
                case 8:  // ACFC
                    break;
                case 3: {
                    int proto = l >= 4 ? Bytes.u16(p, o + 2) : 0;
                    if (proto == PROTO_PAP && l == 4) {
                        newAuth = PROTO_PAP;
                    } else if (proto == PROTO_CHAP && l == 5
                            && ((p[o + 4] & 0xff) == CHAP_MSV2 || (p[o + 4] & 0xff) == CHAP_MD5)) {
                        newAuth = PROTO_CHAP;
                        newAlg = p[o + 4] & 0xff;
                    } else {
                        nak.u8(3).u8(5).u16(PROTO_CHAP).u8(CHAP_MSV2);
                    }
                    break;
                }
                default:
                    rej.bytes(p, o, l);
            }
            o += l;
        }
        if (rej.size() > 0) {
            sendCp(PROTO_LCP, CONF_REJ, id, rej.toByteArray());
        } else if (nak.size() > 0) {
            sendCp(PROTO_LCP, CONF_NAK, id, nak.toByteArray());
        } else {
            byte[] opts = new byte[len];
            System.arraycopy(p, off, opts, 0, len);
            sendCp(PROTO_LCP, CONF_ACK, id, opts);
            authProto = newAuth;
            chapAlg = newAlg;
            peerMru = newMru;
            lcpAckSent = true;
            maybeLcpOpen();
        }
    }

    private void maybeLcpOpen() {
        if (!(lcpAckRcvd && lcpAckSent) || phase != Phase.LCP) return;
        String a = authProto == PROTO_PAP ? "PAP" : authProto == PROTO_CHAP
                ? (chapAlg == CHAP_MSV2 ? "MS-CHAPv2" : "CHAP-MD5") : "none";
        log("LCP open (peer MRU " + peerMru + ", auth " + a + ")");
        startEcho();
        if (authProto == 0) {
            authDone = true;
            startNetwork();
        } else {
            phase = Phase.AUTH;
            if (authProto == PROTO_PAP) sendPap();
            // For CHAP we wait for the server's Challenge.
        }
    }

    // ------------------------------------------------------------------ auth

    private void sendPap() {
        byte[] u = username.getBytes(StandardCharsets.UTF_8);
        byte[] pw = password.getBytes(StandardCharsets.UTF_8);
        byte[] data = new Bytes.Writer().u8(u.length).bytes(u).u8(pw.length).bytes(pw).toByteArray();
        sendCp(PROTO_PAP, 1, id(), data);
        papTimer = host.schedule(() -> {
            if (phase != Phase.AUTH) return;
            if (++papTries >= MAX_CONFIGURE) {
                fail("no reply to PAP authentication", false);
                return;
            }
            sendPap();
        }, RESTART_MS);
    }

    private void onPap(byte[] p, int off, int len) {
        if (len < 4) return;
        int code = p[off] & 0xff;
        if (papTimer != null) papTimer.cancel(false);
        if (code == 2) {
            log("PAP authentication succeeded");
            authDone = true;
            startNetwork();
        } else if (code == 3) {
            fail("authentication failed — check username and password", true);
        }
    }

    private void onChap(byte[] p, int off, int len) {
        if (len < 4) return;
        int code = p[off] & 0xff;
        int id = p[off + 1] & 0xff;
        int plen = Math.min(Bytes.u16(p, off + 2), len);
        if (code == 1) {  // Challenge
            if (plen < 5) return;
            int vs = p[off + 4] & 0xff;
            if (5 + vs > plen) return;
            byte[] challenge = Bytes.slice(p, off + 5, vs);
            byte[] name = username.getBytes(StandardCharsets.UTF_8);
            byte[] value;
            if (chapAlg == CHAP_MSV2) {
                if (vs != 16) {
                    fail("bad MS-CHAPv2 challenge size " + vs, false);
                    return;
                }
                mschap = new MsChapV2(challenge, username, password);
                value = mschap.responseValue();
            } else {
                value = Crypto.digest("MD5", new byte[] {(byte) id},
                        password.getBytes(StandardCharsets.UTF_8), challenge);
            }
            byte[] data = new Bytes.Writer().u8(value.length).bytes(value).bytes(name).toByteArray();
            sendCp(PROTO_CHAP, 2, id, data);
        } else if (code == 3) {  // Success
            if (phase != Phase.AUTH) return;
            String msg = new String(p, off + 4, plen - 4, StandardCharsets.UTF_8);
            if (chapAlg == CHAP_MSV2 && (mschap == null || !mschap.verifySuccess(msg))) {
                fail("server failed MS-CHAPv2 mutual authentication — refusing to continue", true);
                return;
            }
            log((chapAlg == CHAP_MSV2 ? "MS-CHAPv2" : "CHAP") + " authentication succeeded");
            authDone = true;
            startNetwork();
        } else if (code == 4) {  // Failure
            String msg = new String(p, off + 4, plen - 4, StandardCharsets.UTF_8);
            fail(describeChapFailure(msg), true);
        }
    }

    private static String describeChapFailure(String msg) {
        if (msg.contains("E=648")) return "authentication failed: password expired";
        if (msg.contains("E=649")) return "authentication failed: account has no dial-in permission";
        if (msg.contains("E=647")) return "authentication failed: account disabled";
        if (msg.contains("E=646")) return "authentication failed: logon hours restriction";
        return "authentication failed — check username and password";
    }

    // ------------------------------------------------------------------ IPCP

    private void startNetwork() {
        phase = Phase.NETWORK;
        if (!ipcpStarted) {
            ipcpStarted = true;
            sendIpcpRequest();
        }
    }

    private void sendIpcpRequest() {
        Bytes.Writer w = new Bytes.Writer();
        w.u8(3).u8(6).bytes(reqIp);
        if (askDns1) w.u8(129).u8(6).bytes(reqDns1);
        if (askDns2) w.u8(131).u8(6).bytes(reqDns2);
        ipcpReqId = id();
        sendCp(PROTO_IPCP, CONF_REQ, ipcpReqId, w.toByteArray());
        if (ipcpTimer != null) ipcpTimer.cancel(false);
        ipcpTimer = host.schedule(() -> {
            if (phase != Phase.NETWORK || ipcpAckRcvd) return;
            if (++ipcpTries >= MAX_CONFIGURE) {
                fail("IPCP negotiation timed out", false);
                return;
            }
            sendIpcpRequest();
        }, RESTART_MS);
    }

    private void onIpcp(byte[] p, int off, int len) {
        if (len < 4) return;
        int code = p[off] & 0xff;
        int id = p[off + 1] & 0xff;
        int plen = Math.min(Bytes.u16(p, off + 2), len);
        int dOff = off + 4, dLen = plen - 4;
        if (code == CONF_REQ) {
            if (phase == Phase.OPEN) {
                fail("server restarted IP negotiation", false);
                return;
            }
            Bytes.Writer rej = new Bytes.Writer();
            for (int o = dOff; o + 2 <= dOff + dLen; ) {
                int t = p[o] & 0xff, l = p[o + 1] & 0xff;
                if (l < 2 || o + l > dOff + dLen) break;
                if (t != 3) rej.bytes(p, o, l);  // accept only IP-Address
                o += l;
            }
            if (rej.size() > 0) {
                sendCp(PROTO_IPCP, CONF_REJ, id, rej.toByteArray());
            } else {
                sendCp(PROTO_IPCP, CONF_ACK, id, Bytes.slice(p, dOff, dLen));
                ipcpAckSent = true;
                maybeIpcpOpen();
            }
        } else if (code == CONF_ACK && id == ipcpReqId) {
            ipcpAckRcvd = true;
            if (ipcpTimer != null) ipcpTimer.cancel(false);
            maybeIpcpOpen();
        } else if ((code == CONF_NAK || code == CONF_REJ) && id == ipcpReqId) {
            for (int o = dOff; o + 2 <= dOff + dLen; ) {
                int t = p[o] & 0xff, l = p[o + 1] & 0xff;
                if (l < 2 || o + l > dOff + dLen) break;
                if (code == CONF_NAK && l == 6) {
                    byte[] v = Bytes.slice(p, o + 2, 4);
                    if (t == 3) reqIp = v;
                    else if (t == 129) reqDns1 = v;
                    else if (t == 131) reqDns2 = v;
                } else if (code == CONF_REJ) {
                    if (t == 3) {
                        fail("server refused to assign an IP address", false);
                        return;
                    }
                    if (t == 129) askDns1 = false;
                    if (t == 131) askDns2 = false;
                }
                o += l;
            }
            sendIpcpRequest();
        } else if (code == TERM_REQ) {
            sendCp(PROTO_IPCP, TERM_ACK, id, new byte[0]);
            fail("server closed IP negotiation", false);
        }
    }

    private void maybeIpcpOpen() {
        if (!(ipcpAckRcvd && ipcpAckSent) || phase != Phase.NETWORK) return;
        phase = Phase.OPEN;
        List<byte[]> dns = new ArrayList<>();
        if (askDns1 && !isZero(reqDns1)) dns.add(reqDns1);
        if (askDns2 && !isZero(reqDns2)) dns.add(reqDns2);
        StringBuilder sb = new StringBuilder();
        for (byte[] d : dns) sb.append(' ').append(Bytes.ip(d));
        log("IPCP open: address " + Bytes.ip(reqIp) + ", DNS" + (dns.isEmpty() ? " none" : sb.toString()));
        host.onPppUp(reqIp, dns, peerMru);
    }

    private static boolean isZero(byte[] a) {
        for (byte b : a) if (b != 0) return false;
        return true;
    }

    // ------------------------------------------------------------------ keepalive

    private void startEcho() {
        echoTimer = host.schedule(() -> {
            if (phase == Phase.DEAD) return;
            if (System.currentTimeMillis() - lastRx >= ECHO_MS - 500) {
                if (echoOutstanding >= ECHO_FAILURES) {
                    fail("server stopped answering (no LCP echo replies)", false);
                    return;
                }
                echoOutstanding++;
                sendCp(PROTO_LCP, ECHO_REQ, id(), Bytes.be32(magic));
            } else {
                echoOutstanding = 0;
            }
            startEcho();
        }, ECHO_MS);
    }

    /**
     * Verifies quickly that the PPP session survived an IPsec re-establishment;
     * fails the link if the server stays silent for ~6 seconds.
     */
    public void probe() {
        if (phase != Phase.OPEN) return;
        sendProbe(System.currentTimeMillis(), 0);
    }

    private void sendProbe(long mark, int tries) {
        sendCp(PROTO_LCP, ECHO_REQ, id(), Bytes.be32(magic));
        host.schedule(() -> {
            if (phase != Phase.OPEN || lastRx >= mark) return;
            if (tries + 1 >= 3) {
                fail("server lost our session after IPsec was re-established", false);
            } else {
                sendProbe(mark, tries + 1);
            }
        }, 2000);
    }

    /** Called by the engine when IP data arrives, which proves the link is alive. */
    public void noteDataReceived() {
        lastRx = System.currentTimeMillis();
    }

    public boolean isOpen() {
        return phase == Phase.OPEN;
    }
}
