package net.daniellehmann.l2tpvpn.core;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Algorithm descriptors and primitives used by IKEv1 and ESP. Everything goes
 * through the platform JCE (Conscrypt on Android), except DH which is plain
 * BigInteger math over the RFC 2409/3526 MODP groups.
 */
public final class Crypto {
    private Crypto() {}

    /** CBC block cipher usable for both IKE and ESP. */
    public static final class Enc {
        public final String name;
        public final int ikeId;     // IKEv1 Encryption Algorithm attribute value
        public final int espId;     // IPsec DOI ESP transform id
        public final int keyBytes;
        public final boolean keyLengthAttr;  // AES needs an explicit Key Length attribute
        public final int block;
        private final String jce;

        Enc(String name, int ikeId, int espId, int keyBytes, boolean keyLengthAttr, int block, String jce) {
            this.name = name;
            this.ikeId = ikeId;
            this.espId = espId;
            this.keyBytes = keyBytes;
            this.keyLengthAttr = keyLengthAttr;
            this.block = block;
            this.jce = jce;
        }

        public Cipher init(boolean encrypt, byte[] key, byte[] iv) throws GeneralSecurityException {
            Cipher c = Cipher.getInstance(jce + "/CBC/NoPadding");
            c.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, jce), new IvParameterSpec(iv));
            return c;
        }

        public byte[] crypt(boolean encrypt, byte[] key, byte[] iv, byte[] data, int off, int len)
                throws GeneralSecurityException {
            return init(encrypt, key, iv).doFinal(data, off, len);
        }

        @Override public String toString() { return name; }
    }

    public static final Enc AES256 = new Enc("aes256", 7, 12, 32, true, 16, "AES");
    public static final Enc AES128 = new Enc("aes128", 7, 12, 16, true, 16, "AES");
    public static final Enc TDES = new Enc("3des", 5, 3, 24, false, 8, "DESede");

    /** IKEv1 hash/PRF algorithm (the PRF is HMAC with the hash). */
    public static final class Prf {
        public final String name;
        public final int ikeId;
        public final String mac;
        public final int outLen;

        Prf(String name, int ikeId, String mac, int outLen) {
            this.name = name;
            this.ikeId = ikeId;
            this.mac = mac;
            this.outLen = outLen;
        }

        public byte[] prf(byte[] key, byte[]... data) {
            return hmac(mac, key, data);
        }

        /** The plain hash, used for phase 1 IV derivation. */
        public byte[] hash(byte[]... data) {
            try {
                MessageDigest md = MessageDigest.getInstance(mac.replace("Hmac", "").replace("SHA", "SHA-"));
                for (byte[] d : data) md.update(d);
                return md.digest();
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
        }

        @Override public String toString() { return name; }
    }

    public static final Prf SHA1 = new Prf("sha1", 2, "HmacSHA1", 20);
    public static final Prf SHA256 = new Prf("sha256", 4, "HmacSHA256", 32);
    public static final Prf SHA384 = new Prf("sha384", 5, "HmacSHA384", 48);
    public static final Prf SHA512 = new Prf("sha512", 6, "HmacSHA512", 64);

    /** ESP integrity algorithm (truncated HMAC). */
    public static final class Integ {
        public final String name;
        public final int authId;    // IPsec DOI Authentication Algorithm attribute
        public final String mac;
        public final int keyBytes;
        public final int icvLen;

        Integ(String name, int authId, String mac, int keyBytes, int icvLen) {
            this.name = name;
            this.authId = authId;
            this.mac = mac;
            this.keyBytes = keyBytes;
            this.icvLen = icvLen;
        }

        @Override public String toString() { return name; }
    }

    public static final Integ HMAC_SHA1_96 = new Integ("sha1", 2, "HmacSHA1", 20, 12);
    public static final Integ HMAC_SHA256_128 = new Integ("sha256", 5, "HmacSHA256", 32, 16);
    public static final Integ HMAC_SHA384_192 = new Integ("sha384", 6, "HmacSHA384", 48, 24);
    public static final Integ HMAC_SHA512_256 = new Integ("sha512", 7, "HmacSHA512", 64, 32);
    public static final Integ HMAC_MD5_96 = new Integ("md5", 1, "HmacMD5", 16, 12);

    /** Finite-field Diffie-Hellman group. */
    public static final class DhGroup {
        public final int id;
        public final BigInteger p;
        public final int bytes;

        DhGroup(int id, String hex) {
            this.id = id;
            this.p = new BigInteger(hex, 16);
            this.bytes = (p.bitLength() + 7) / 8;
        }

        public BigInteger newPrivate() {
            BigInteger x;
            do {
                x = new BigInteger(p.bitLength() - 1, Bytes.RNG);
            } while (x.bitLength() < 160);
            return x;
        }

        public byte[] publicValue(BigInteger x) {
            return pad(BigInteger.valueOf(2).modPow(x, p));
        }

        public byte[] shared(BigInteger x, byte[] peerPublic) {
            BigInteger y = new BigInteger(1, peerPublic);
            if (y.compareTo(BigInteger.ONE) <= 0 || y.compareTo(p.subtract(BigInteger.ONE)) >= 0) {
                throw new IllegalArgumentException("invalid DH public value");
            }
            return pad(y.modPow(x, p));
        }

        private byte[] pad(BigInteger v) {
            byte[] raw = v.toByteArray();
            byte[] out = new byte[bytes];
            int n = Math.min(raw.length, bytes);
            System.arraycopy(raw, raw.length - n, out, bytes - n, n);
            return out;
        }

        @Override public String toString() { return "modp" + (bytes * 8); }
    }

    private static final String MODP_2 =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
            + "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
            + "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";

    private static final String MODP_5 =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
            + "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
            + "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
            + "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
            + "9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";

    private static final String MODP_14 =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
            + "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
            + "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
            + "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
            + "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
            + "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

    private static final String MODP_15 =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
            + "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
            + "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
            + "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
            + "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
            + "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
            + "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
            + "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
            + "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
            + "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

    private static final String MODP_16 =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
            + "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
            + "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
            + "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
            + "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
            + "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33"
            + "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
            + "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864"
            + "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2"
            + "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
            + "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8"
            + "DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
            + "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
            + "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF";

    public static final DhGroup MODP1024 = new DhGroup(2, MODP_2);
    public static final DhGroup MODP1536 = new DhGroup(5, MODP_5);
    public static final DhGroup MODP2048 = new DhGroup(14, MODP_14);
    public static final DhGroup MODP3072 = new DhGroup(15, MODP_15);
    public static final DhGroup MODP4096 = new DhGroup(16, MODP_16);

    public static DhGroup group(int id) {
        for (DhGroup g : new DhGroup[] {MODP1024, MODP1536, MODP2048, MODP3072, MODP4096}) {
            if (g.id == id) return g;
        }
        return null;
    }

    public static byte[] hmac(String alg, byte[] key, byte[]... data) {
        try {
            Mac m = Mac.getInstance(alg);
            m.init(new SecretKeySpec(key.length == 0 ? new byte[1] : key, alg));
            for (byte[] d : data) m.update(d);
            return m.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] digest(String alg, byte[]... data) {
        try {
            MessageDigest md = MessageDigest.getInstance(alg);
            for (byte[] d : data) md.update(d);
            return md.digest();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
