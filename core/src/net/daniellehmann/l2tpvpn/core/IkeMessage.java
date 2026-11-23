package net.daniellehmann.l2tpvpn.core;

import java.util.ArrayList;
import java.util.List;

/** ISAKMP (RFC 2408) message: a fixed header plus a chain of generic payloads. */
public final class IkeMessage {
    public static final int HDR_LEN = 28;

    // Exchange types
    public static final int EXCH_MAIN = 2;
    public static final int EXCH_INFO = 5;
    public static final int EXCH_QUICK = 32;

    // Flags
    public static final int FLAG_ENC = 0x01;
    public static final int FLAG_COMMIT = 0x02;

    // Payload types
    public static final int P_SA = 1;
    public static final int P_PROPOSAL = 2;
    public static final int P_TRANSFORM = 3;
    public static final int P_KE = 4;
    public static final int P_ID = 5;
    public static final int P_HASH = 8;
    public static final int P_NONCE = 10;
    public static final int P_N = 11;
    public static final int P_D = 12;
    public static final int P_VID = 13;
    public static final int P_NATD = 20;
    public static final int P_NATOA = 21;
    public static final int P_NATD_DRAFT = 130;
    public static final int P_NATOA_DRAFT = 131;

    public static final class Payload {
        public final int type;
        public final byte[] body;
        /** Offset of this payload's generic header within the (decrypted) message. */
        public int offset;

        public Payload(int type, byte[] body) {
            this.type = type;
            this.body = body;
        }

        public int encodedLength() {
            return 4 + body.length;
        }
    }

    public byte[] icookie;
    public byte[] rcookie;
    public int exchange;
    public int flags;
    public int msgId;
    public final List<Payload> payloads = new ArrayList<>();
    /** Decrypted/plain message bytes covering header + payloads (no padding). */
    public byte[] raw;
    /** End offset of the last payload in raw (where hashing input stops). */
    public int payloadEnd;

    public IkeMessage() {}

    public IkeMessage(byte[] icookie, byte[] rcookie, int exchange, int flags, int msgId) {
        this.icookie = icookie;
        this.rcookie = rcookie;
        this.exchange = exchange;
        this.flags = flags;
        this.msgId = msgId;
    }

    public IkeMessage add(int type, byte[] body) {
        payloads.add(new Payload(type, body));
        return this;
    }

    public Payload find(int type) {
        for (Payload p : payloads) if (p.type == type) return p;
        return null;
    }

    public List<Payload> findAll(int type) {
        List<Payload> out = new ArrayList<>();
        for (Payload p : payloads) if (p.type == type) out.add(p);
        return out;
    }

    /** Encodes payloads (no header) in chain order. */
    public static byte[] encodePayloads(List<Payload> list) {
        Bytes.Writer w = new Bytes.Writer();
        for (int i = 0; i < list.size(); i++) {
            Payload p = list.get(i);
            int next = i + 1 < list.size() ? list.get(i + 1).type : 0;
            w.u8(next).u8(0).u16(p.encodedLength()).bytes(p.body);
        }
        return w.toByteArray();
    }

    public byte[] header(int totalLen) {
        byte[] h = new byte[HDR_LEN];
        System.arraycopy(icookie, 0, h, 0, 8);
        System.arraycopy(rcookie, 0, h, 8, 8);
        h[16] = (byte) (payloads.isEmpty() ? 0 : payloads.get(0).type);
        h[17] = 0x10;
        h[18] = (byte) exchange;
        h[19] = (byte) flags;
        Bytes.put32(h, 20, msgId);
        Bytes.put32(h, 24, totalLen);
        return h;
    }

    /** Plain (unencrypted) encoding. */
    public byte[] encode() {
        byte[] body = encodePayloads(payloads);
        return Bytes.concat(header(HDR_LEN + body.length), body);
    }

    /** Parses the fixed header only; payloads are parsed after optional decryption. */
    public static IkeMessage parseHeader(byte[] b, int off, int len) throws ProtocolException {
        if (len < HDR_LEN) throw new ProtocolException("short ISAKMP message");
        IkeMessage m = new IkeMessage();
        m.icookie = Bytes.slice(b, off, 8);
        m.rcookie = Bytes.slice(b, off + 8, 8);
        m.exchange = Bytes.u8(b, off + 18);
        m.flags = Bytes.u8(b, off + 19);
        m.msgId = Bytes.u32(b, off + 20);
        int declared = Bytes.u32(b, off + 24);
        if ((b[off + 17] & 0xf0) != 0x10) throw new ProtocolException("not IKEv1");
        if (declared < HDR_LEN || declared > len) throw new ProtocolException("bad ISAKMP length");
        return m;
    }

    /**
     * Parses the payload chain from {@code plain}, which holds the 28-byte header
     * followed by payloads (decrypted if needed, possibly with trailing padding).
     */
    public void parsePayloads(byte[] plain) throws ProtocolException {
        raw = plain;
        int next = Bytes.u8(plain, 16);
        int off = HDR_LEN;
        payloads.clear();
        while (next != 0) {
            if (off + 4 > plain.length) throw new ProtocolException("truncated payload chain");
            int plen = Bytes.u16(plain, off + 2);
            if (plen < 4 || off + plen > plain.length) throw new ProtocolException("bad payload length");
            Payload p = new Payload(next, Bytes.slice(plain, off + 4, plen - 4));
            p.offset = off;
            payloads.add(p);
            next = Bytes.u8(plain, off);
            off += plen;
        }
        payloadEnd = off;
    }

    // ---- SA payload / attribute helpers ----

    /** One transform attribute; basic (TV) when the value fits in 16 bits. */
    public static void attr(Bytes.Writer w, int type, int value) {
        if (value >= 0 && value <= 0xffff) {
            w.u16(0x8000 | type).u16(value);
        } else {
            w.u16(type).u16(4).u32(value);
        }
    }

    /** Parsed transform: id plus attribute map (type -> value). */
    public static final class Transform {
        public int number;
        public int id;
        public final java.util.Map<Integer, Integer> attrs = new java.util.LinkedHashMap<>();

        public int get(int type, int def) {
            Integer v = attrs.get(type);
            return v == null ? def : v;
        }
    }

    /** Parsed proposal of an SA payload. */
    public static final class Proposal {
        public int number;
        public int protocol;
        public byte[] spi;
        public final List<Transform> transforms = new ArrayList<>();
    }

    public static List<Proposal> parseSa(byte[] body) throws ProtocolException {
        if (body.length < 8) throw new ProtocolException("short SA payload");
        List<Proposal> out = new ArrayList<>();
        int off = 8;
        int next = P_PROPOSAL;
        while (next == P_PROPOSAL && off + 8 <= body.length) {
            next = Bytes.u8(body, off);
            int plen = Bytes.u16(body, off + 2);
            if (plen < 8 || off + plen > body.length) throw new ProtocolException("bad proposal length");
            Proposal p = new Proposal();
            p.number = Bytes.u8(body, off + 4);
            p.protocol = Bytes.u8(body, off + 5);
            int spiSize = Bytes.u8(body, off + 6);
            int nt = Bytes.u8(body, off + 7);
            p.spi = Bytes.slice(body, off + 8, spiSize);
            int t = off + 8 + spiSize;
            for (int i = 0; i < nt; i++) {
                if (t + 8 > off + plen) throw new ProtocolException("truncated transform");
                int tlen = Bytes.u16(body, t + 2);
                if (tlen < 8 || t + tlen > off + plen) throw new ProtocolException("bad transform length");
                Transform tr = new Transform();
                tr.number = Bytes.u8(body, t + 4);
                tr.id = Bytes.u8(body, t + 5);
                int a = t + 8;
                while (a + 4 <= t + tlen) {
                    int at = Bytes.u16(body, a);
                    if ((at & 0x8000) != 0) {
                        tr.attrs.put(at & 0x7fff, Bytes.u16(body, a + 2));
                        a += 4;
                    } else {
                        int alen = Bytes.u16(body, a + 2);
                        if (a + 4 + alen > t + tlen) throw new ProtocolException("bad attribute length");
                        int v = 0;
                        for (int k = 0; k < alen && k < 4; k++) v = (v << 8) | Bytes.u8(body, a + 4 + alen - Math.min(alen, 4) + k);
                        tr.attrs.put(at, v);
                        a += 4 + alen;
                    }
                }
                p.transforms.add(tr);
                t += tlen;
            }
            out.add(p);
            off += plen;
        }
        return out;
    }

    /** Builds an SA payload body (DOI IPsec, SIT_IDENTITY_ONLY) with one proposal. */
    public static byte[] buildSa(int proposalNo, int protocol, byte[] spi, List<byte[]> transformBodies,
                                 int transformPayloadType) {
        Bytes.Writer transforms = new Bytes.Writer();
        for (int i = 0; i < transformBodies.size(); i++) {
            byte[] tb = transformBodies.get(i);
            int next = i + 1 < transformBodies.size() ? transformPayloadType : 0;
            transforms.u8(next).u8(0).u16(4 + tb.length).bytes(tb);
        }
        byte[] tr = transforms.toByteArray();
        Bytes.Writer w = new Bytes.Writer();
        w.u32(1).u32(1);  // DOI = IPSEC, Situation = SIT_IDENTITY_ONLY
        w.u8(0).u8(0).u16(8 + spi.length + tr.length)
                .u8(proposalNo).u8(protocol).u8(spi.length).u8(transformBodies.size())
                .bytes(spi).bytes(tr);
        return w.toByteArray();
    }

    /** Notify payload body. */
    public static byte[] notifyBody(int protocol, byte[] spi, int type, byte[] data) {
        return new Bytes.Writer().u32(1).u8(protocol).u8(spi.length).u16(type)
                .bytes(spi).bytes(data).toByteArray();
    }

    public static String notifyName(int t) {
        switch (t) {
            case 14: return "NO_PROPOSAL_CHOSEN";
            case 16: return "PAYLOAD_MALFORMED";
            case 17: return "INVALID_KEY_INFORMATION";
            case 18: return "INVALID_ID_INFORMATION";
            case 23: return "INVALID_HASH_INFORMATION";
            case 24: return "AUTHENTICATION_FAILED";
            case 28: return "UNEQUAL_PAYLOAD_LENGTHS";
            case 24576: return "RESPONDER_LIFETIME";
            case 24578: return "INITIAL_CONTACT";
            case 36136: return "R_U_THERE";
            case 36137: return "R_U_THERE_ACK";
            default: return "notify " + t;
        }
    }
}
