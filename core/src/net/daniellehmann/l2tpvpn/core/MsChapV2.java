package net.daniellehmann.l2tpvpn.core;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Locale;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** MS-CHAPv2 (RFC 2759) response generation and server authenticator check. */
public final class MsChapV2 {
    private static final byte[] MAGIC1 =
            "Magic server to client signing constant".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] MAGIC2 =
            "Pad to make it do more than one iteration".getBytes(StandardCharsets.US_ASCII);

    public final byte[] peerChallenge;
    public final byte[] ntResponse;
    private final byte[] expectedAuthenticator;

    public MsChapV2(byte[] authChallenge, String username, String password) {
        this(authChallenge, Bytes.random(16), username, password);
    }

    MsChapV2(byte[] authChallenge, byte[] peerChallenge, String username, String password) {
        this.peerChallenge = peerChallenge;
        byte[] pwHash = Md4.digest(password.getBytes(StandardCharsets.UTF_16LE));
        byte[] chHash = challengeHash(peerChallenge, authChallenge, username);
        this.ntResponse = challengeResponse(chHash, pwHash);

        byte[] pwHashHash = Md4.digest(pwHash);
        byte[] digest = Crypto.digest("SHA-1", pwHashHash, ntResponse, MAGIC1);
        this.expectedAuthenticator = Crypto.digest("SHA-1", digest, chHash, MAGIC2);
    }

    /** The 49-byte CHAP Value field: PeerChallenge, 8 reserved, NT-Response, Flags. */
    public byte[] responseValue() {
        return Bytes.concat(peerChallenge, new byte[8], ntResponse, new byte[1]);
    }

    /** Checks the "S=<40 hex>" authenticator in a CHAP Success message. */
    public boolean verifySuccess(String message) {
        int i = message.indexOf("S=");
        if (i < 0 || message.length() < i + 42) return false;
        String got = message.substring(i + 2, i + 42).toUpperCase(Locale.ROOT);
        String want = Bytes.hex(expectedAuthenticator).toUpperCase(Locale.ROOT);
        byte[] a = got.getBytes(StandardCharsets.US_ASCII);
        byte[] b = want.getBytes(StandardCharsets.US_ASCII);
        return Bytes.equal(a, 0, b, 0, 40);
    }

    private static byte[] challengeHash(byte[] peerChallenge, byte[] authChallenge, String username) {
        // RFC 2759 hashes the user name without any "DOMAIN\" prefix.
        int bs = username.lastIndexOf('\\');
        String user = bs >= 0 ? username.substring(bs + 1) : username;
        byte[] h = Crypto.digest("SHA-1", peerChallenge, authChallenge,
                user.getBytes(StandardCharsets.UTF_8));
        return Bytes.slice(h, 0, 8);
    }

    private static byte[] challengeResponse(byte[] challenge, byte[] pwHash) {
        byte[] z = new byte[21];
        System.arraycopy(pwHash, 0, z, 0, 16);
        return Bytes.concat(
                des(Bytes.slice(z, 0, 7), challenge),
                des(Bytes.slice(z, 7, 7), challenge),
                des(Bytes.slice(z, 14, 7), challenge));
    }

    /**
     * Single DES of one block. Expressed as 3DES with K1=K2=K3 in CBC mode with a
     * zero IV, because that is what every Android JCE provider reliably offers.
     */
    static byte[] des(byte[] key7, byte[] block) {
        byte[] k = expandKey(key7);
        byte[] k3 = Bytes.concat(k, k, k);
        try {
            Cipher c = Cipher.getInstance("DESede/CBC/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k3, "DESede"), new IvParameterSpec(new byte[8]));
            return c.doFinal(block);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] expandKey(byte[] s) {
        byte[] k = new byte[8];
        k[0] = (byte) (s[0] & 0xfe);
        k[1] = (byte) ((s[0] << 7) | ((s[1] & 0xff) >>> 1));
        k[2] = (byte) ((s[1] << 6) | ((s[2] & 0xff) >>> 2));
        k[3] = (byte) ((s[2] << 5) | ((s[3] & 0xff) >>> 3));
        k[4] = (byte) ((s[3] << 4) | ((s[4] & 0xff) >>> 4));
        k[5] = (byte) ((s[4] << 3) | ((s[5] & 0xff) >>> 5));
        k[6] = (byte) ((s[5] << 2) | ((s[6] & 0xff) >>> 6));
        k[7] = (byte) (s[6] << 1);
        for (int i = 0; i < 8; i++) k[i] &= (byte) 0xfe;
        return k;
    }
}
