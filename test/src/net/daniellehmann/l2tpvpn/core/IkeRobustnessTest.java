package net.daniellehmann.l2tpvpn.core;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ScheduledFuture;

/**
 * Regression tests for the security review: forged or malformed Phase 1 input
 * from an on-path attacker must never fail the session (H1, L1) or escape the
 * parser as an unchecked exception (M1).
 */
public final class IkeRobustnessTest {
    static int failed;
    static String failure;

    static IkeSession session() {
        failure = null;
        IkeSession.Host h = new IkeSession.Host() {
            @Override public void sendIke(byte[] p, boolean natt) {}
            @Override public ScheduledFuture<?> schedule(Runnable r, long ms) { return null; }
            @Override public void log(String m) {}
            @Override public void onIkeEstablished(IkeSession s) {}
            @Override public void onIkeFailed(IkeSession s, String reason, boolean permanent) {
                failure = reason + (permanent ? " [permanent]" : "");
            }
            @Override public void onIkeDeleted(IkeSession s) { failure = "deleted"; }
            @Override public void onPeerChildSa(IkeSession s, ChildSa c) {}
            @Override public void onChildDeleted(IkeSession s, int spi) {}
        };
        IkeSession s = new IkeSession(h, 1, "psk".getBytes(), new byte[] {10, 0, 0, 2}, new byte[] {10, 0, 0, 1}, true);
        s.start();
        return s;
    }

    static void expectAlive(String name, IkeSession s, byte[] pkt) {
        try {
            s.onPacket(pkt);
        } catch (RuntimeException e) {
            failure = "threw " + e;
        }
        boolean ok = failure == null && !s.isDead();
        if (!ok) failed++;
        System.out.println((ok ? "PASS " : "FAIL ") + name + (ok ? "" : " -> " + failure));
    }

    static byte[] msg(byte[] ic, byte[] rc, int exch, int flags, int nextPayload, byte[] payloads) {
        byte[] h = new byte[IkeMessage.HDR_LEN];
        System.arraycopy(ic, 0, h, 0, 8);
        System.arraycopy(rc, 0, h, 8, 8);
        h[16] = (byte) nextPayload;
        h[17] = 0x10;
        h[18] = (byte) exch;
        h[19] = (byte) flags;
        Bytes.put32(h, 24, h.length + payloads.length);
        return Bytes.concat(h, payloads);
    }

    static byte[] notifyPayload(int type) {
        byte[] body = IkeMessage.notifyBody(1, new byte[0], type, new byte[0]);
        List<IkeMessage.Payload> l = new ArrayList<>();
        l.add(new IkeMessage.Payload(IkeMessage.P_N, body));
        return IkeMessage.encodePayloads(l);
    }

    public static void main(String[] a) {
        IkeSession s = session();
        expectAlive("forged plaintext AUTHENTICATION_FAILED after MM1", s,
                msg(s.icookie, new byte[8], IkeMessage.EXCH_INFO, 0, IkeMessage.P_N, notifyPayload(24)));

        s = session();
        expectAlive("forged plaintext NO_PROPOSAL_CHOSEN after MM1", s,
                msg(s.icookie, new byte[8], IkeMessage.EXCH_INFO, 0, IkeMessage.P_N, notifyPayload(14)));

        s = session();
        expectAlive("forged encrypted INFO before keys exist", s,
                msg(s.icookie, Bytes.random(8), IkeMessage.EXCH_INFO, IkeMessage.FLAG_ENC, IkeMessage.P_HASH, new byte[16]));

        // MM2 whose SA carries a long-form attribute claiming 32767 bytes.
        s = session();
        Bytes.Writer t = new Bytes.Writer().u8(1).u8(1).u16(0).u16(0x0001).u16(0x7fff).u32(0);
        byte[] tb = t.toByteArray();
        List<byte[]> trs = new ArrayList<>();
        trs.add(tb);
        byte[] sa = IkeMessage.buildSa(1, 1, new byte[0], trs, IkeMessage.P_TRANSFORM);
        List<IkeMessage.Payload> pl = new ArrayList<>();
        pl.add(new IkeMessage.Payload(IkeMessage.P_SA, sa));
        expectAlive("MM2 with overlong TLV attribute", s,
                msg(s.icookie, Bytes.random(8), IkeMessage.EXCH_MAIN, 0, IkeMessage.P_SA, IkeMessage.encodePayloads(pl)));

        s = session();
        expectAlive("random garbage after valid header", s,
                msg(s.icookie, Bytes.random(8), IkeMessage.EXCH_MAIN, 0, IkeMessage.P_SA, Bytes.random(64)));

        System.exit(failed == 0 ? 0 : 1);
    }
}
