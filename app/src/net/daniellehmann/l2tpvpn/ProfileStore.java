package net.daniellehmann.l2tpvpn;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import net.daniellehmann.l2tpvpn.core.Config;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Persists the single VPN profile in app-private storage. The pre-shared key
 * and password are encrypted with a non-exportable AES key held in the Android
 * Keystore, so they are useless if the preferences file is copied off-device.
 */
public final class ProfileStore {
    private static final String PREFS = "profile";
    private static final String KEY_ALIAS = "l2tpvpn-secrets";

    private ProfileStore() {}

    private static SharedPreferences prefs(Context c) {
        return c.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public static boolean exists(Context c) {
        return prefs(c).contains("server");
    }

    public static Config load(Context c) {
        SharedPreferences p = prefs(c);
        Config cfg = new Config();
        cfg.server = p.getString("server", "");
        cfg.username = p.getString("username", "");
        cfg.dnsOverride = p.getString("dns", "");
        cfg.mtu = p.getInt("mtu", 0);
        cfg.vmProxy = p.getBoolean("vmProxy", false);
        cfg.psk = decrypt(p.getString("psk", ""));
        cfg.password = decrypt(p.getString("password", ""));
        return cfg;
    }

    public static void save(Context c, Config cfg) {
        prefs(c).edit()
                .putString("server", cfg.server.trim())
                .putString("username", cfg.username)
                .putString("dns", cfg.dnsOverride.trim())
                .putInt("mtu", cfg.mtu)
                .putBoolean("vmProxy", cfg.vmProxy)
                .putString("psk", encrypt(cfg.psk))
                .putString("password", encrypt(cfg.password))
                .apply();
    }

    private static SecretKey key() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (ks.containsAlias(KEY_ALIAS)) {
            return ((KeyStore.SecretKeyEntry) ks.getEntry(KEY_ALIAS, null)).getSecretKey();
        }
        KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        kg.init(new KeyGenParameterSpec.Builder(KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build());
        return kg.generateKey();
    }

    private static String encrypt(String plain) {
        if (plain.isEmpty()) return "";
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key());
            byte[] iv = c.getIV();
            byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
            byte[] out = new byte[1 + iv.length + ct.length];
            out[0] = (byte) iv.length;
            System.arraycopy(iv, 0, out, 1, iv.length);
            System.arraycopy(ct, 0, out, 1 + iv.length, ct.length);
            return Base64.encodeToString(out, Base64.NO_WRAP);
        } catch (Exception e) {
            throw new IllegalStateException("Keystore encryption failed", e);
        }
    }

    private static String decrypt(String stored) {
        if (stored.isEmpty()) return "";
        try {
            byte[] in = Base64.decode(stored, Base64.NO_WRAP);
            int ivLen = in[0];
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, in, 1, ivLen));
            return new String(c.doFinal(in, 1 + ivLen, in.length - 1 - ivLen), StandardCharsets.UTF_8);
        } catch (Exception e) {
            VpnState.log("cannot decrypt a stored secret (" + e.getClass().getSimpleName() + "); please re-enter it");
            return "";
        }
    }
}
