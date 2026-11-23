package net.daniellehmann.l2tpvpn.core;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledFuture;

import static net.daniellehmann.l2tpvpn.core.IkeMessage.*;

/**
 * One IKEv1 ISAKMP SA, always as initiator of Main Mode with a pre-shared key.
 * Quick Mode runs as initiator (our connects and rekeys) and as responder
 * (server-initiated rekeys). NAT traversal is always forced so that ESP rides
 * in UDP/4500 — Android apps cannot send raw ESP.
 *
 * Not thread-safe: every method must run on the engine's control thread.
 */
public final class IkeSession {
    /** Callbacks into the engine. All invoked on the control thread. */
    public interface Host {
        void sendIke(byte[] packet, boolean nattPort);
        ScheduledFuture<?> schedule(Runnable r, long delayMs);
        void log(String msg);
        void onIkeEstablished(IkeSession s);
        void onIkeFailed(IkeSession s, String reason, boolean permanent);
        void onIkeDeleted(IkeSession s);
        void onPeerChildSa(IkeSession s, ChildSa child);
        void onChildDeleted(IkeSession s, int spiOut);
    }

    public interface QuickModeCallback {
        void established(ChildSa child);
        void failed(String reason, int notifyType);
    }

    private static final byte[] VID_RFC3947 = Bytes.unhex("4a131c81070358455c5728f20e95452f");
    private static final byte[] VID_NATT_DRAFT02 = Bytes.unhex("90cb80913ebb696e086381b5ec427b1f");
    private static final byte[] VID_NATT_DRAFT02N = Bytes.unhex("cd60464335df21f87cfdb2fc68b6a448");
    private static final byte[] VID_DPD = Bytes.unhex("afcad71368a1f1c96b8696fc77570100");

    static final int PROTO_ISAKMP = 1;
    static final int PROTO_ESP = 3;
    static final int N_INITIAL_CONTACT = 24578;
    static final int N_RESPONDER_LIFETIME = 24576;
    static final int N_R_U_THERE = 36136;
    static final int N_R_U_THERE_ACK = 36137;

    private static final long[] RETRANSMIT_MS = {1000, 2000, 4000, 8000, 8000};
    public static final int PHASE1_LIFETIME = 28800;
    public static final int PHASE2_LIFETIME = 3600;

    private enum State { NEW, MM1_SENT, MM3_SENT, MM5_SENT, ESTABLISHED, DEAD }

    /** Phase 1 transform proposal. */
    private static final class P1 {
        final Crypto.Enc enc; final Crypto.Prf prf; final Crypto.DhGroup group;
        P1(Crypto.Enc e, Crypto.Prf p, Crypto.DhGroup g) { enc = e; prf = p; group = g; }
    }

    /** Phase 2 transform proposal. */
    private static final class P2 {
        final Crypto.Enc enc; final Crypto.Integ integ;
        P2(Crypto.Enc e, Crypto.Integ i) { enc = e; integ = i; }
    }

    private static final List<P1> P1_OFFERS = new ArrayList<>();
    private static final List<P2> P2_OFFERS = new ArrayList<>();
    static {
        Crypto.DhGroup[] strong = {Crypto.MODP2048, Crypto.MODP3072, Crypto.MODP4096, Crypto.MODP1536};
        for (Crypto.DhGroup g : strong) {
            for (Crypto.Prf h : new Crypto.Prf[] {Crypto.SHA256, Crypto.SHA1, Crypto.SHA384, Crypto.SHA512}) {
                for (Crypto.Enc e : new Crypto.Enc[] {Crypto.AES256, Crypto.AES128}) {
                    if (g != Crypto.MODP2048 && h != Crypto.SHA256 && h != Crypto.SHA1) continue;
                    P1_OFFERS.add(new P1(e, h, g));
                }
            }
            if (g == Crypto.MODP2048) P1_OFFERS.add(new P1(Crypto.TDES, Crypto.SHA1, g));
        }
        // Legacy group 2 is still the default on many appliances.
        for (Crypto.Prf h : new Crypto.Prf[] {Crypto.SHA256, Crypto.SHA1}) {
            P1_OFFERS.add(new P1(Crypto.AES256, h, Crypto.MODP1024));
            P1_OFFERS.add(new P1(Crypto.AES128, h, Crypto.MODP1024));
        }
        P1_OFFERS.add(new P1(Crypto.TDES, Crypto.SHA1, Crypto.MODP1024));

        for (Crypto.Integ i : new Crypto.Integ[] {Crypto.HMAC_SHA256_128, Crypto.HMAC_SHA1_96,
                Crypto.HMAC_SHA512_256, Crypto.HMAC_SHA384_192}) {
            P2_OFFERS.add(new P2(Crypto.AES256, i));
            P2_OFFERS.add(new P2(Crypto.AES128, i));
        }
        P2_OFFERS.add(new P2(Crypto.TDES, Crypto.HMAC_SHA1_96));
    }

    private final Host host;
    private final byte[] psk;
    private final byte[] localIp;
    private final byte[] remoteIp;
    private final boolean initialContact;
    public final int serial;

    public final byte[] icookie = Bytes.random(8);
    private byte[] rcookie = new byte[8];
    private State state = State.NEW;

    private Crypto.Enc enc;
    private Crypto.Prf prf;
    private Crypto.DhGroup group;
    private BigInteger dhX;
    private byte[] gxi, gxr, ni, nr, saiBody, idiiBody;
    private byte[] skeyid, skeyidD, skeyidA, encKey;
    private byte[] iv;        // running IV during Main Mode
    private byte[] phase1Iv;  // last CBC block of the final Main Mode message
    private boolean nattDraft;
    private boolean peerDpd;
    public long establishedAt;
    public volatile long lastPeerActivity;

    private Pending pending;
    private String hint;
    private final Map<Integer, QuickMode> quickModes = new HashMap<>();

    public IkeSession(Host host, int serial, byte[] psk, byte[] localIp, byte[] remoteIp, boolean initialContact) {
        this.host = host;
        this.serial = serial;
        this.psk = psk;
        this.localIp = localIp;
        this.remoteIp = remoteIp;
        this.initialContact = initialContact;
    }

    public boolean isEstablished() {
        return state == State.ESTABLISHED;
    }

    public boolean isDead() {
        return state == State.DEAD;
    }

    public boolean matches(byte[] ic) {
        return Bytes.equal(ic, 0, icookie, 0, 8);
    }

    public String describe() {
        return enc + "-" + prf + "-" + group;
    }

    private void log(String s) {
        host.log("IKE#" + serial + ": " + s);
    }

    // ------------------------------------------------------------------ Main Mode

    public void start() {
        List<byte[]> transforms = new ArrayList<>();
        for (int i = 0; i < P1_OFFERS.size(); i++) {
            P1 o = P1_OFFERS.get(i);
            Bytes.Writer w = new Bytes.Writer().u8(i + 1).u8(1).u16(0);  // KEY_IKE
            attr(w, 1, o.enc.ikeId);
            if (o.enc.keyLengthAttr) attr(w, 14, o.enc.keyBytes * 8);
            attr(w, 2, o.prf.ikeId);
            attr(w, 3, 1);  // pre-shared key
            attr(w, 4, o.group.id);
            attr(w, 11, 1);  // seconds
            attr(w, 12, PHASE1_LIFETIME);
            transforms.add(w.toByteArray());
        }
        saiBody = buildSa(1, PROTO_ISAKMP, new byte[0], transforms, P_TRANSFORM);
        IkeMessage m = new IkeMessage(icookie, rcookie, EXCH_MAIN, 0, 0)
                .add(P_SA, saiBody)
                .add(P_VID, VID_RFC3947)
                .add(P_VID, VID_NATT_DRAFT02N)
                .add(P_VID, VID_NATT_DRAFT02)
                .add(P_VID, VID_DPD);
        state = State.MM1_SENT;
        log("sending Main Mode 1 (" + P1_OFFERS.size() + " proposals)");
        send(m.encode(), false, "Main Mode 1");
    }

    private void onMm2(IkeMessage m) throws ProtocolException {
        Payload sa = m.find(P_SA);
        if (sa == null) throw new ProtocolException("Main Mode 2 without SA");
        List<Proposal> props = parseSa(sa.body);
        if (props.isEmpty() || props.get(0).transforms.isEmpty()) throw new ProtocolException("empty SA in reply");
        Transform t = props.get(0).transforms.get(0);
        P1 chosen = null;
        for (P1 o : P1_OFFERS) {
            if (t.get(1, -1) == o.enc.ikeId && t.get(2, -1) == o.prf.ikeId && t.get(4, -1) == o.group.id
                    && (!o.enc.keyLengthAttr || t.get(14, -1) == o.enc.keyBytes * 8)) {
                chosen = o;
                break;
            }
        }
        if (chosen == null || t.get(3, -1) != 1) throw new ProtocolException("server chose a transform we did not offer");
        enc = chosen.enc;
        prf = chosen.prf;
        group = chosen.group;

        boolean rfc = false, draft = false;
        for (Payload v : m.findAll(P_VID)) {
            if (java.util.Arrays.equals(v.body, VID_RFC3947)) rfc = true;
            else if (java.util.Arrays.equals(v.body, VID_NATT_DRAFT02) || java.util.Arrays.equals(v.body, VID_NATT_DRAFT02N)) draft = true;
            else if (java.util.Arrays.equals(v.body, VID_DPD)) peerDpd = true;
        }
        if (!rfc && !draft) {
            throw new ProtocolException("server does not support NAT traversal (required: Android cannot send raw ESP)");
        }
        nattDraft = !rfc;
        rcookie = m.rcookie;
        log("server chose " + describe() + (nattDraft ? ", NAT-T draft-02" : ", NAT-T RFC 3947")
                + (peerDpd ? ", DPD" : ""));

        dhX = group.newPrivate();
        gxi = group.publicValue(dhX);
        ni = Bytes.random(32);
        int natdType = nattDraft ? P_NATD_DRAFT : P_NATD;
        // First NAT-D describes the server (as we address it); the second one is
        // ours. We deliberately send a bogus hash for ourselves so the server always
        // believes we are behind NAT and uses UDP-encapsulated ESP.
        byte[] natdRemote = prf.hash(icookie, rcookie, remoteIp, new byte[] {0x01, (byte) 0xf4});
        byte[] natdLocal = Bytes.random(prf.outLen);
        IkeMessage out = new IkeMessage(icookie, rcookie, EXCH_MAIN, 0, 0)
                .add(P_KE, gxi)
                .add(P_NONCE, ni)
                .add(natdType, natdRemote)
                .add(natdType, natdLocal);
        state = State.MM3_SENT;
        send(out.encode(), false, "Main Mode 3");
    }

    private void onMm4(IkeMessage m) throws ProtocolException, GeneralSecurityException {
        Payload ke = m.find(P_KE), nonce = m.find(P_NONCE);
        if (ke == null || nonce == null) throw new ProtocolException("Main Mode 4 missing KE/nonce");
        gxr = ke.body;
        nr = nonce.body;
        byte[] gxy = group.shared(dhX, gxr);

        skeyid = prf.prf(psk, ni, nr);
        skeyidD = prf.prf(skeyid, gxy, icookie, rcookie, new byte[] {0});
        skeyidA = prf.prf(skeyid, skeyidD, gxy, icookie, rcookie, new byte[] {1});
        byte[] skeyidE = prf.prf(skeyid, skeyidA, gxy, icookie, rcookie, new byte[] {2});
        encKey = expandKey(skeyidE, enc.keyBytes);
        iv = Bytes.slice(prf.hash(gxi, gxr), 0, enc.block);

        idiiBody = Bytes.concat(new byte[] {1, 0, 0, 0}, localIp);  // ID_IPV4_ADDR, proto 0, port 0
        byte[] hashI = prf.prf(skeyid, gxi, gxr, icookie, rcookie, saiBody, idiiBody);
        IkeMessage out = new IkeMessage(icookie, rcookie, EXCH_MAIN, FLAG_ENC, 0)
                .add(P_ID, idiiBody)
                .add(P_HASH, hashI);
        if (initialContact) {
            out.add(P_N, notifyBody(PROTO_ISAKMP, Bytes.concat(icookie, rcookie), N_INITIAL_CONTACT, new byte[0]));
        }
        byte[][] ivOut = new byte[1][];
        byte[] pkt = encrypt(out, iv, ivOut);
        iv = ivOut[0];
        state = State.MM5_SENT;
        send(pkt, true, "Main Mode 5");
    }

    private void onMm6(IkeMessage m, byte[] nextIv) throws ProtocolException {
        Payload id = m.find(P_ID), hash = m.find(P_HASH);
        if (id == null || hash == null) throw new ProtocolException("Main Mode 6 missing ID/HASH");
        byte[] want = prf.prf(skeyid, gxr, gxi, rcookie, icookie, saiBody, id.body);
        if (!Bytes.equal(want, 0, hash.body, 0, want.length) || hash.body.length != want.length) {
            throw new ProtocolException("server's reply failed authentication — the pre-shared key may be wrong");
        }
        phase1Iv = nextIv;
        cancelPending();
        state = State.ESTABLISHED;
        establishedAt = System.currentTimeMillis();
        lastPeerActivity = establishedAt;
        log("established, server ID " + describeId(id.body));
        host.onIkeEstablished(this);
    }

    private static String describeId(byte[] b) {
        if (b.length >= 8 && b[0] == 1) return Bytes.ip(Bytes.slice(b, 4, 4));
        if (b.length > 4 && (b[0] == 2 || b[0] == 3)) {
            return new String(b, 4, b.length - 4, StandardCharsets.UTF_8);
        }
        return "type " + (b.length > 0 ? b[0] : -1);
    }

    private byte[] expandKey(byte[] seed, int len) {
        if (seed.length >= len) return Bytes.slice(seed, 0, len);
        Bytes.Writer w = new Bytes.Writer();
        byte[] k = prf.prf(seed, new byte[] {0});
        w.bytes(k);
        while (w.size() < len) {
            k = prf.prf(seed, k);
            w.bytes(k);
        }
        return Bytes.slice(w.toByteArray(), 0, len);
    }

    // ------------------------------------------------------------------ crypto

    private byte[] encrypt(IkeMessage m, byte[] ivIn, byte[][] ivOut) throws GeneralSecurityException {
        byte[] body = encodePayloads(m.payloads);
        int padded = ((body.length + enc.block - 1) / enc.block) * enc.block;
        byte[] plain = new byte[padded];
        System.arraycopy(body, 0, plain, 0, body.length);
        byte[] ct = enc.crypt(true, encKey, ivIn, plain, 0, padded);
        ivOut[0] = Bytes.slice(ct, ct.length - enc.block, enc.block);
        return Bytes.concat(m.header(HDR_LEN + ct.length), ct);
    }

    /** Decrypts in place into a fresh plain buffer; returns the new running IV. */
    private byte[] decrypt(IkeMessage m, byte[] pkt, byte[] ivIn) throws ProtocolException {
        int declared = Bytes.u32(pkt, 24);
        int ctLen = declared - HDR_LEN;
        if (ctLen <= 0 || ctLen % enc.block != 0) throw new ProtocolException("encrypted length not block aligned");
        byte[] pt;
        try {
            pt = enc.crypt(false, encKey, ivIn, pkt, HDR_LEN, ctLen);
        } catch (GeneralSecurityException e) {
            throw new ProtocolException("decryption failed", e);
        }
        m.parsePayloads(Bytes.concat(Bytes.slice(pkt, 0, HDR_LEN), pt));
        return Bytes.slice(pkt, HDR_LEN + ctLen - enc.block, enc.block);
    }

    private byte[] phase2Iv(int msgId) {
        return Bytes.slice(prf.hash(phase1Iv, Bytes.be32(msgId)), 0, enc.block);
    }

    /** Bytes following the first (HASH) payload, up to the end of the last payload. */
    private static byte[] afterHash(IkeMessage m) {
        Payload h = m.payloads.get(0);
        int start = h.offset + 4 + h.body.length;
        return Bytes.slice(m.raw, start, m.payloadEnd - start);
    }

    // ------------------------------------------------------------------ dispatch

    /** Handles one IKE packet (without non-ESP marker) addressed to this session. */
    public void onPacket(byte[] pkt) {
        if (state == State.DEAD) return;
        IkeMessage m;
        try {
            m = IkeMessage.parseHeader(pkt, 0, pkt.length);
            pkt = Bytes.slice(pkt, 0, Bytes.u32(pkt, 24));
        } catch (ProtocolException e) {
            log("dropping malformed packet: " + e.getMessage());
            return;
        }
        if (state != State.MM1_SENT && !Bytes.equal(m.rcookie, 0, rcookie, 0, 8)) return;
        // Until Main Mode completes, nothing we receive is authenticated: an on-path
        // attacker can forge it. Such input may only leave a diagnostic hint; the
        // exchange keeps retransmitting and fails (non-permanently) on timeout.
        try {
            if (m.exchange == EXCH_INFO) {
                onInformational(m, pkt);
            } else if (m.exchange == EXCH_MAIN) {
                onMainMode(m, pkt);
            } else if (m.exchange == EXCH_QUICK && state == State.ESTABLISHED) {
                onQuickMode(m, pkt);
            }
        } catch (ProtocolException | GeneralSecurityException | RuntimeException e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            if (state != State.ESTABLISHED && state != State.DEAD) {
                hint(msg);
            } else {
                log("dropped packet: " + msg);
            }
        }
    }

    private void onMainMode(IkeMessage m, byte[] pkt) throws ProtocolException, GeneralSecurityException {
        boolean encrypted = (m.flags & FLAG_ENC) != 0;
        switch (state) {
            case MM1_SENT:
                if (encrypted) return;
                m.parsePayloads(pkt);
                cancelPending();
                onMm2(m);
                break;
            case MM3_SENT:
                if (encrypted) return;
                m.parsePayloads(pkt);
                if (m.find(P_KE) == null) return;  // retransmitted MM2
                cancelPending();
                onMm4(m);
                break;
            case MM5_SENT:
                if (!encrypted) return;
                IkeMessage copy;
                byte[] next;
                try {
                    copy = IkeMessage.parseHeader(pkt, 0, pkt.length);
                    next = decrypt(copy, pkt, iv);
                } catch (ProtocolException e) {
                    throw new ProtocolException("cannot decrypt the server's reply — the pre-shared key may be wrong", e);
                }
                // Commit the IV only once HASH_R has authenticated the message.
                onMm6(copy, next);
                break;
            default:
                break;
        }
    }

    private void onInformational(IkeMessage m, byte[] pkt) throws ProtocolException {
        if ((m.flags & FLAG_ENC) != 0) {
            if (state != State.ESTABLISHED) {
                // Usually the server rejecting our HASH_I (wrong PSK), but it cannot
                // be verified, so it is only a hint.
                if (state == State.MM5_SENT) hint("server rejected our authentication — check the pre-shared key");
                return;
            }
            decrypt(m, pkt, phase2Iv(m.msgId));
            Payload hash = m.payloads.isEmpty() ? null : m.payloads.get(0);
            if (hash == null || hash.type != P_HASH) throw new ProtocolException("informational without HASH");
            byte[] want = prf.prf(skeyidA, Bytes.be32(m.msgId), afterHash(m));
            if (hash.body.length != want.length || !Bytes.equal(want, 0, hash.body, 0, want.length)) {
                throw new ProtocolException("informational HASH mismatch");
            }
        } else {
            m.parsePayloads(pkt);
        }
        lastPeerActivity = System.currentTimeMillis();
        for (Payload p : m.payloads) {
            if (p.type == P_N && p.body.length >= 8) {
                int type = Bytes.u16(p.body, 6);
                int spiSize = Bytes.u8(p.body, 5);
                byte[] data = p.body.length > 8 + spiSize ? Bytes.slice(p.body, 8 + spiSize, p.body.length - 8 - spiSize) : new byte[0];
                onNotify(type, data, (m.flags & FLAG_ENC) != 0);
            } else if (p.type == P_D && p.body.length >= 8 && (m.flags & FLAG_ENC) != 0) {
                onDelete(p.body);
            }
        }
    }

    private void onNotify(int type, byte[] data, boolean authenticated) {
        if (type == N_R_U_THERE && authenticated) {
            IkeMessage ack = new IkeMessage(icookie, rcookie, EXCH_INFO, 0, 0)
                    .add(P_N, notifyBody(PROTO_ISAKMP, Bytes.concat(icookie, rcookie), N_R_U_THERE_ACK, data));
            sendInformational(ack);
            return;
        }
        if (type == N_R_U_THERE_ACK || type == N_INITIAL_CONTACT) return;
        if (!authenticated) {
            // Plaintext notifies can be forged by anyone on the path: never act on them.
            if (type < 16384 && state != State.ESTABLISHED) hint("server refused: " + notifyName(type));
            else log("ignoring unauthenticated notify: " + notifyName(type));
            return;
        }
        log("server notify: " + notifyName(type));
        if (type < 16384) {  // error notifications
            for (QuickMode q : new ArrayList<>(quickModes.values())) {
                if (q.initiator && q.state == QuickMode.SENT1) q.fail("server refused: " + notifyName(type), type);
            }
        }
    }

    private void onDelete(byte[] b) {
        int proto = Bytes.u8(b, 4);
        int spiSize = Bytes.u8(b, 5);
        int n = Bytes.u16(b, 6);
        for (int i = 0; i < n && 8 + (i + 1) * spiSize <= b.length; i++) {
            if (proto == PROTO_ISAKMP) {
                log("server deleted this IKE SA");
                state = State.DEAD;
                cancelAll();
                host.onIkeDeleted(this);
                return;
            } else if (proto == PROTO_ESP && spiSize == 4) {
                int spi = Bytes.u32(b, 8 + i * 4);
                log(String.format("server deleted ESP SA %08x", spi));
                host.onChildDeleted(this, spi);
            }
        }
    }

    private void sendInformational(IkeMessage m) {
        m.msgId = Bytes.RNG.nextInt() | 1;
        m.flags = FLAG_ENC;
        byte[] rest = encodePayloads(m.payloads);
        byte[] hash = prf.prf(skeyidA, Bytes.be32(m.msgId), rest);
        m.payloads.add(0, new Payload(P_HASH, hash));
        try {
            host.sendIke(encrypt(m, phase2Iv(m.msgId), new byte[1][]), true);
        } catch (GeneralSecurityException e) {
            log("cannot encrypt informational: " + e);
        }
    }

    public void deleteChild(ChildSa c) {
        if (state != State.ESTABLISHED) return;
        byte[] body = new Bytes.Writer().u32(1).u8(PROTO_ESP).u8(4).u16(1).u32(c.spiIn).toByteArray();
        sendInformational(new IkeMessage(icookie, rcookie, EXCH_INFO, 0, 0).add(P_D, body));
    }

    /** Sends a Delete for this ISAKMP SA and stops all activity. */
    public void delete() {
        if (state == State.ESTABLISHED) {
            byte[] body = new Bytes.Writer().u32(1).u8(PROTO_ISAKMP).u8(16).u16(1)
                    .bytes(icookie).bytes(rcookie).toByteArray();
            sendInformational(new IkeMessage(icookie, rcookie, EXCH_INFO, 0, 0).add(P_D, body));
        }
        state = State.DEAD;
        cancelAll();
    }

    // ------------------------------------------------------------------ Quick Mode

    private final class QuickMode {
        static final int SENT1 = 1, SENT2 = 2, DONE = 3;
        final int msgId;
        final boolean initiator;
        int state;
        byte[] iv;
        byte[] qni, qnr;
        int spiIn, spiOut;
        P2 chosen;
        Crypto.DhGroup pfs;
        BigInteger x;
        byte[] gqm;  // PFS shared secret, or null
        byte[] lastSent;
        QuickModeCallback cb;
        Pending retx;
        ScheduledFuture<?> expire;

        QuickMode(int msgId, boolean initiator) {
            this.msgId = msgId;
            this.initiator = initiator;
        }

        void fail(String reason, int notifyType) {
            finish();
            if (cb != null) cb.failed(reason, notifyType);
        }

        void finish() {
            state = DONE;
            if (retx != null) retx.cancel();
            // Keep the record a little longer so retransmitted peer messages are answered.
            if (expire == null) expire = host.schedule(() -> quickModes.remove(msgId), 30000);
        }
    }

    private static int newSpi() {
        int s;
        do {
            s = Bytes.RNG.nextInt();
        } while ((s & 0xffffff00) == 0);
        return s;
    }

    private static int encapMode(boolean draft) {
        return draft ? 61444 : 4;  // UDP-Encapsulated-Transport
    }

    /**
     * Starts an initiator Quick Mode for L2TP (UDP/1701) in transport mode.
     * @param pfs     include a KE payload using the phase 1 group
     * @param withIds send IDci/IDcr; some servers prefer them omitted
     */
    public void startQuickMode(boolean pfs, boolean withIds, QuickModeCallback cb) {
        int msgId = Bytes.RNG.nextInt() | 1;
        QuickMode q = new QuickMode(msgId, true);
        q.cb = cb;
        q.spiIn = newSpi();
        q.qni = Bytes.random(32);
        q.pfs = pfs ? group : null;
        quickModes.put(msgId, q);

        List<byte[]> transforms = new ArrayList<>();
        for (int i = 0; i < P2_OFFERS.size(); i++) {
            P2 o = P2_OFFERS.get(i);
            Bytes.Writer w = new Bytes.Writer().u8(i + 1).u8(o.enc.espId).u16(0);
            attr(w, 1, 1);  // SA life type: seconds
            attr(w, 2, PHASE2_LIFETIME);
            if (q.pfs != null) attr(w, 3, q.pfs.id);
            attr(w, 4, encapMode(nattDraft));
            attr(w, 5, o.integ.authId);
            if (o.enc.keyLengthAttr) attr(w, 6, o.enc.keyBytes * 8);
            transforms.add(w.toByteArray());
        }
        List<Payload> rest = new ArrayList<>();
        rest.add(new Payload(P_SA, buildSa(1, PROTO_ESP, Bytes.be32(q.spiIn), transforms, P_TRANSFORM)));
        rest.add(new Payload(P_NONCE, q.qni));
        if (q.pfs != null) {
            q.x = q.pfs.newPrivate();
            rest.add(new Payload(P_KE, q.pfs.publicValue(q.x)));
        }
        if (withIds) {
            rest.add(new Payload(P_ID, Bytes.concat(new byte[] {1, 17, 0x06, (byte) 0xa5}, localIp)));
            rest.add(new Payload(P_ID, Bytes.concat(new byte[] {1, 17, 0x06, (byte) 0xa5}, remoteIp)));
        }
        int oaType = nattDraft ? P_NATOA_DRAFT : P_NATOA;
        rest.add(new Payload(oaType, Bytes.concat(new byte[] {1, 0, 0, 0}, localIp)));
        rest.add(new Payload(oaType, Bytes.concat(new byte[] {1, 0, 0, 0}, remoteIp)));

        byte[] hash1 = prf.prf(skeyidA, Bytes.be32(msgId), encodePayloads(rest));
        IkeMessage m = new IkeMessage(icookie, rcookie, EXCH_QUICK, FLAG_ENC, msgId);
        m.add(P_HASH, hash1);
        m.payloads.addAll(rest);
        try {
            byte[][] ivOut = new byte[1][];
            byte[] pkt = encrypt(m, phase2Iv(msgId), ivOut);
            q.iv = ivOut[0];
            q.state = QuickMode.SENT1;
            q.lastSent = pkt;
            log("sending Quick Mode 1" + (pfs ? " (PFS " + group + ")" : "") + (withIds ? "" : " without IDs"));
            q.retx = new Pending(pkt, true, "Quick Mode 1", () -> q.fail("no response to Quick Mode", 0));
            q.retx.start();
        } catch (GeneralSecurityException e) {
            q.fail("encrypt: " + e, 0);
        }
    }

    private void onQuickMode(IkeMessage m, byte[] pkt) throws ProtocolException, GeneralSecurityException {
        QuickMode q = quickModes.get(m.msgId);
        lastPeerActivity = System.currentTimeMillis();
        if (q == null) {
            onPeerQuickMode1(m, pkt);
            return;
        }
        if (q.state == QuickMode.DONE) {
            // Peer retransmitted because our last message got lost: repeat it.
            if (q.lastSent != null) host.sendIke(q.lastSent, true);
            return;
        }
        if (q.initiator && q.state == QuickMode.SENT1) {
            q.iv = decrypt(m, pkt, q.iv);
            onQuickMode2(q, m);
        } else if (!q.initiator && q.state == QuickMode.SENT2) {
            decrypt(m, pkt, q.iv);
            Payload h = m.find(P_HASH);
            byte[] want = prf.prf(skeyidA, new byte[] {0}, Bytes.be32(q.msgId), q.qni, q.qnr);
            if (h == null || h.body.length != want.length || !Bytes.equal(want, 0, h.body, 0, want.length)) {
                throw new ProtocolException("Quick Mode 3 HASH mismatch");
            }
            q.finish();
            ChildSa child = makeChild(q);
            log("server-initiated rekey complete: " + child);
            host.onPeerChildSa(this, child);
        }
    }

    private void onQuickMode2(QuickMode q, IkeMessage m) throws ProtocolException, GeneralSecurityException {
        Payload h = m.payloads.isEmpty() ? null : m.payloads.get(0);
        if (h == null || h.type != P_HASH) throw new ProtocolException("Quick Mode 2 without HASH");
        byte[] want = prf.prf(skeyidA, Bytes.be32(q.msgId), q.qni, afterHash(m));
        if (h.body.length != want.length || !Bytes.equal(want, 0, h.body, 0, want.length)) {
            throw new ProtocolException("Quick Mode 2 HASH mismatch");
        }
        Payload sa = m.find(P_SA), nonce = m.find(P_NONCE);
        if (sa == null || nonce == null) throw new ProtocolException("Quick Mode 2 missing SA/nonce");
        List<Proposal> props = parseSa(sa.body);
        if (props.isEmpty() || props.get(0).transforms.isEmpty() || props.get(0).spi.length != 4) {
            throw new ProtocolException("bad SA in Quick Mode 2");
        }
        Transform t = props.get(0).transforms.get(0);
        q.chosen = matchP2(t);
        if (q.chosen == null) throw new ProtocolException("server chose an ESP transform we did not offer");
        q.spiOut = Bytes.u32(props.get(0).spi, 0);
        q.qnr = nonce.body;
        if (q.pfs != null) {
            Payload ke = m.find(P_KE);
            if (ke == null) throw new ProtocolException("PFS requested but no KE in Quick Mode 2");
            q.gqm = q.pfs.shared(q.x, ke.body);
        }
        for (Payload p : m.findAll(P_N)) {
            if (p.body.length >= 8 && Bytes.u16(p.body, 6) == N_RESPONDER_LIFETIME) log("server sent RESPONDER-LIFETIME");
        }

        byte[] hash3 = prf.prf(skeyidA, new byte[] {0}, Bytes.be32(q.msgId), q.qni, q.qnr);
        IkeMessage out = new IkeMessage(icookie, rcookie, EXCH_QUICK, FLAG_ENC, q.msgId).add(P_HASH, hash3);
        byte[][] ivOut = new byte[1][];
        byte[] pkt = encrypt(out, q.iv, ivOut);
        q.lastSent = pkt;
        host.sendIke(pkt, true);
        q.finish();
        ChildSa child = makeChild(q);
        log("Quick Mode done: " + child);
        q.cb.established(child);
    }

    private P2 matchP2(Transform t) {
        for (P2 o : P2_OFFERS) {
            if (t.id == o.enc.espId && t.get(5, -1) == o.integ.authId
                    && (!o.enc.keyLengthAttr || t.get(6, -1) == o.enc.keyBytes * 8)) {
                return o;
            }
        }
        return null;
    }

    private void onPeerQuickMode1(IkeMessage m, byte[] pkt) throws ProtocolException, GeneralSecurityException {
        byte[] ivAfter = decrypt(m, pkt, phase2Iv(m.msgId));
        Payload h = m.payloads.isEmpty() ? null : m.payloads.get(0);
        if (h == null || h.type != P_HASH) throw new ProtocolException("peer Quick Mode 1 without HASH");
        byte[] want = prf.prf(skeyidA, Bytes.be32(m.msgId), afterHash(m));
        if (h.body.length != want.length || !Bytes.equal(want, 0, h.body, 0, want.length)) {
            throw new ProtocolException("peer Quick Mode 1 HASH mismatch");
        }
        Payload sa = m.find(P_SA), nonce = m.find(P_NONCE);
        if (sa == null || nonce == null) throw new ProtocolException("peer Quick Mode 1 missing SA/nonce");

        QuickMode q = new QuickMode(m.msgId, false);
        q.qni = nonce.body;
        Proposal chosenProp = null;
        Transform chosenT = null;
        for (Proposal p : parseSa(sa.body)) {
            if (p.protocol != PROTO_ESP || p.spi.length != 4) continue;
            for (Transform t : p.transforms) {
                int mode = t.get(4, -1);
                if (mode != 4 && mode != 61444 && mode != 2) continue;
                P2 o = matchP2(t);
                if (o != null) {
                    chosenProp = p;
                    chosenT = t;
                    q.chosen = o;
                    break;
                }
            }
            if (chosenProp != null) break;
        }
        if (chosenProp == null) {
            log("rejecting server-initiated Quick Mode: no acceptable transform");
            return;
        }
        q.spiOut = Bytes.u32(chosenProp.spi, 0);
        q.spiIn = newSpi();
        q.qnr = Bytes.random(32);
        Payload ke = m.find(P_KE);
        byte[] ourKe = null;
        if (ke != null) {
            q.pfs = Crypto.group(chosenT.get(3, group.id));
            if (q.pfs == null) throw new ProtocolException("peer asked for unsupported PFS group");
            q.x = q.pfs.newPrivate();
            ourKe = q.pfs.publicValue(q.x);
            q.gqm = q.pfs.shared(q.x, ke.body);
        }

        Bytes.Writer tw = new Bytes.Writer().u8(chosenT.number).u8(chosenT.id).u16(0);
        for (Map.Entry<Integer, Integer> a : chosenT.attrs.entrySet()) attr(tw, a.getKey(), a.getValue());
        List<byte[]> one = new ArrayList<>();
        one.add(tw.toByteArray());

        List<Payload> rest = new ArrayList<>();
        rest.add(new Payload(P_SA, buildSa(chosenProp.number, PROTO_ESP, Bytes.be32(q.spiIn), one, P_TRANSFORM)));
        rest.add(new Payload(P_NONCE, q.qnr));
        if (ourKe != null) rest.add(new Payload(P_KE, ourKe));
        for (Payload p : m.findAll(P_ID)) rest.add(new Payload(P_ID, p.body));
        byte[] hash2 = prf.prf(skeyidA, Bytes.be32(m.msgId), q.qni, encodePayloads(rest));
        IkeMessage out = new IkeMessage(icookie, rcookie, EXCH_QUICK, FLAG_ENC, m.msgId);
        out.add(P_HASH, hash2);
        out.payloads.addAll(rest);
        byte[][] ivOut = new byte[1][];
        byte[] reply = encrypt(out, ivAfter, ivOut);
        q.iv = ivOut[0];
        q.state = QuickMode.SENT2;
        q.lastSent = reply;
        quickModes.put(m.msgId, q);
        log("answering server-initiated Quick Mode (" + q.chosen.enc + "/" + q.chosen.integ + ")");
        host.sendIke(reply, true);
        // The initiator retransmits QM1 until it sees QM2, so no timer needed;
        // just forget the exchange if QM3 never arrives.
        q.expire = host.schedule(() -> quickModes.remove(q.msgId), 60000);
    }

    private ChildSa makeChild(QuickMode q) {
        int need = q.chosen.enc.keyBytes + q.chosen.integ.keyBytes;
        byte[] ni = q.initiator ? q.qni : q.qni;  // qni is always the initiator nonce
        byte[] in = keymat(q, q.spiIn, need, ni, q.qnr);
        byte[] out = keymat(q, q.spiOut, need, ni, q.qnr);
        return new ChildSa(this, q.spiIn, q.spiOut, q.chosen.enc, q.chosen.integ, in, out);
    }

    private byte[] keymat(QuickMode q, int spi, int need, byte[] nI, byte[] nR) {
        byte[] seed = Bytes.concat(q.gqm != null ? q.gqm : new byte[0], new byte[] {PROTO_ESP}, Bytes.be32(spi), nI, nR);
        Bytes.Writer w = new Bytes.Writer();
        byte[] k = prf.prf(skeyidD, seed);
        w.bytes(k);
        while (w.size() < need) {
            k = prf.prf(skeyidD, k, seed);
            w.bytes(k);
        }
        return Bytes.slice(w.toByteArray(), 0, need);
    }

    // ------------------------------------------------------------------ retransmission

    private final class Pending {
        final byte[] pkt;
        final boolean natt;
        final String what;
        final Runnable onGiveUp;
        int attempt;
        ScheduledFuture<?> timer;
        boolean cancelled;

        Pending(byte[] pkt, boolean natt, String what, Runnable onGiveUp) {
            this.pkt = pkt;
            this.natt = natt;
            this.what = what;
            this.onGiveUp = onGiveUp;
        }

        void start() {
            host.sendIke(pkt, natt);
            arm();
        }

        void arm() {
            timer = host.schedule(() -> {
                if (cancelled || state == State.DEAD) return;
                if (attempt >= RETRANSMIT_MS.length) {
                    onGiveUp.run();
                    return;
                }
                attempt++;
                log("retransmitting " + what + " (" + attempt + ")");
                host.sendIke(pkt, natt);
                arm();
            }, RETRANSMIT_MS[Math.min(attempt, RETRANSMIT_MS.length - 1)]);
        }

        void cancel() {
            cancelled = true;
            if (timer != null) timer.cancel(false);
        }
    }

    private void send(byte[] pkt, boolean natt, String what) {
        cancelPending();
        State expect = state;
        pending = new Pending(pkt, natt, what, () -> {
            if (state != expect) return;
            if (hint != null) {
                fail(hint, false);
            } else if (expect == State.MM1_SENT) {
                fail("no response from server (UDP 500) — check the server address and that L2TP is enabled", false);
            } else if (expect == State.MM5_SENT) {
                fail("server did not accept our authentication — the pre-shared key is probably wrong", false);
            } else {
                fail("server stopped responding during " + what, false);
            }
        });
        pending.start();
    }

    private void cancelPending() {
        if (pending != null) pending.cancel();
        pending = null;
    }

    private void cancelAll() {
        cancelPending();
        for (QuickMode q : quickModes.values()) {
            if (q.retx != null) q.retx.cancel();
            if (q.expire != null) q.expire.cancel(false);
        }
        quickModes.clear();
    }

    /** Remembers why an unauthenticated message was rejected, for the eventual timeout. */
    private void hint(String reason) {
        if (!reason.equals(hint)) log("ignored unverifiable message: " + reason);
        hint = reason;
    }

    private void fail(String reason, boolean permanent) {
        if (state == State.DEAD) return;
        log("failed: " + reason);
        state = State.DEAD;
        cancelAll();
        host.onIkeFailed(this, reason, permanent);
    }
}
