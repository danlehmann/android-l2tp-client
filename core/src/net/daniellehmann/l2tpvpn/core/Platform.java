package net.daniellehmann.l2tpvpn.core;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.List;

/** What the engine needs from its host (the Android VpnService, or a test harness). */
public interface Platform {
    /** Resolves the server name on the underlying network, never through the VPN. */
    InetAddress resolve(String host) throws IOException;

    /** A bound UDP socket whose traffic bypasses the VPN. */
    DatagramSocket openSocket() throws IOException;

    /** Creates the tunnel interface. The engine closes the previous one itself. */
    Tun establish(TunSettings settings) throws IOException;

    void log(String line);

    void onStatus(Engine.State state, String detail);

    interface Tun {
        /** Blocks until a packet is available; returns -1 once closed. */
        int read(byte[] buf, int off, int len) throws IOException;

        void write(byte[] buf, int off, int len) throws IOException;

        void close();
    }

    final class TunSettings {
        public final byte[] address;
        public final List<byte[]> dns;
        public final int mtu;
        public final String serverAddress;

        public TunSettings(byte[] address, List<byte[]> dns, int mtu, String serverAddress) {
            this.address = address;
            this.dns = dns;
            this.mtu = mtu;
            this.serverAddress = serverAddress;
        }

        public boolean sameAs(TunSettings o) {
            if (o == null || mtu != o.mtu || !java.util.Arrays.equals(address, o.address)
                    || dns.size() != o.dns.size()) {
                return false;
            }
            for (int i = 0; i < dns.size(); i++) {
                if (!java.util.Arrays.equals(dns.get(i), o.dns.get(i))) return false;
            }
            return true;
        }
    }
}
