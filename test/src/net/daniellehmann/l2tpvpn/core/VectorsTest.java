package net.daniellehmann.l2tpvpn.core;

/** Known-answer tests for the hand-written primitives. */
public final class VectorsTest {
    static int failed;

    static void check(String name, String want, byte[] got) {
        boolean ok = want.equalsIgnoreCase(Bytes.hex(got));
        if (!ok) failed++;
        System.out.println((ok ? "PASS " : "FAIL ") + name + (ok ? "" : " got " + Bytes.hex(got)));
    }

    public static void main(String[] a) {
        check("md4(\"\")", "31d6cfe0d16ae931b73c59d7e0c089c0", Md4.digest(new byte[0]));
        check("md4(abc)", "a448017aaf21d8525fc10ae87aa6729d", Md4.digest("abc".getBytes()));
        check("md4(alphabet)", "d79e1c308aa5bbcdeea8ed63df412da9",
                Md4.digest("abcdefghijklmnopqrstuvwxyz".getBytes()));
        // RFC 2759 section 9.2
        MsChapV2 m = new MsChapV2(Bytes.unhex("5B5D7C7D7B3F2F3E3C2C602132262628"),
                Bytes.unhex("21402324255E262A28295F2B3A337C7E"), "User", "clientPass");
        check("mschapv2 NT-Response", "82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF", m.ntResponse);
        boolean ok = m.verifySuccess("S=407A5589115FD0D6209F510FE9C04566932CDA56 M=Access granted");
        boolean bad = m.verifySuccess("S=407A5589115FD0D6209F510FE9C04566932CDA57");
        System.out.println((ok && !bad ? "PASS " : "FAIL ") + "mschapv2 authenticator response");
        if (!ok || bad) failed++;
        // DH sanity: both sides agree
        Crypto.DhGroup g = Crypto.MODP2048;
        java.math.BigInteger x = g.newPrivate(), y = g.newPrivate();
        boolean dh = java.util.Arrays.equals(g.shared(x, g.publicValue(y)), g.shared(y, g.publicValue(x)));
        System.out.println((dh ? "PASS " : "FAIL ") + "modp2048 agreement");
        if (!dh) failed++;
        System.exit(failed == 0 ? 0 : 1);
    }
}
