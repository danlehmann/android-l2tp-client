package net.daniellehmann.l2tpvpn.core;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

/** Connection settings for one VPN profile. */
public final class Config {
    public String server = "";
    public String psk = "";
    public String username = "";
    public String password = "";
    /** Comma/space separated DNS servers that replace the ones the server pushes. */
    public String dnsOverride = "";
    /** Tunnel MTU; 0 picks automatically. */
    public int mtu = 0;
    /** Interval between make-before-break IKE + ESP re-establishment. */
    public int rekeySeconds = 40 * 60;
    /** Offer the tunnel to the device's Linux VM through a SOCKS5 proxy. */
    public boolean vmProxy = false;

    public List<byte[]> parsedDnsOverride() {
        List<byte[]> out = new ArrayList<>();
        for (String s : dnsOverride.split("[,\\s]+")) {
            s = s.trim();
            if (s.isEmpty()) continue;
            if (!s.matches("\\d{1,3}(\\.\\d{1,3}){3}")) continue;
            try {
                out.add(InetAddress.getByName(s).getAddress());
            } catch (Exception ignored) {
                // literal IPv4 never triggers a lookup
            }
        }
        return out;
    }

    /** Returns an error message, or null if the profile is usable. */
    public String validate() {
        if (server.trim().isEmpty()) return "Server address is required";
        if (psk.isEmpty()) return "IPsec pre-shared key is required";
        if (username.isEmpty()) return "Username is required";
        if (password.isEmpty()) return "Password is required";
        if (mtu != 0 && (mtu < 576 || mtu > 1460)) return "MTU must be between 576 and 1460";
        return null;
    }
}
