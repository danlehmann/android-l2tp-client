package net.daniellehmann.l2tpvpn;

import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;

import net.daniellehmann.l2tpvpn.core.Engine;
import net.daniellehmann.l2tpvpn.core.SocksServer;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Lets the Linux VM use the tunnel through a SOCKS5 proxy. Android forwards VM traffic
 * straight to the physical network, and apps cannot change that, so the VM has to ask.
 * The proxy only listens on the VM's virtual link and only accepts addresses on it.
 */
final class VmProxy {
    static final int PORT = 1080;
    private static final String VM_INTERFACE_PREFIX = "avf_tap";
    private static final long RESCAN_MS = 5000;

    private final ConnectivityManager cm;
    private final Thread scanner;
    private volatile boolean stopped;
    private SocksServer server;
    private InterfaceAddress bound;
    private boolean reportedFailure;

    VmProxy(ConnectivityManager cm) {
        this.cm = cm;
        scanner = new Thread(this::scanLoop, "vm-proxy");
        scanner.setDaemon(true);
    }

    void start() {
        scanner.start();
    }

    void stop() {
        stopped = true;
        scanner.interrupt();
    }

    /** The VM link appears and changes as the VM starts and stops, so keep following it. */
    private void scanLoop() {
        while (!stopped) {
            try {
                rebindIfNeeded(findVmAddress());
                Thread.sleep(RESCAN_MS);
            } catch (InterruptedException e) {
                break;
            }
        }
        rebindIfNeeded(null);
    }

    private void rebindIfNeeded(InterfaceAddress current) {
        if (sameAddress(bound, current) && (server != null || current == null)) return;
        if (server != null) {
            server.stop();
            server = null;
            VpnState.log("proxy: stopped");
        }
        if (!sameAddress(bound, current)) reportedFailure = false;
        bound = current;
        if (current == null) return;
        InetAddress self = current.getAddress();
        int prefix = current.getNetworkPrefixLength();
        try {
            server = new SocksServer(self, PORT, this::dial,
                    peer -> !peer.equals(self) && inSubnet(peer, self, prefix), VpnState::log);
            VpnState.log("proxy: for the Linux VM at socks5h://" + self.getHostAddress() + ":" + PORT);
        } catch (IOException e) {
            // Retried on every scan; say so once per address.
            if (!reportedFailure) {
                VpnState.log("proxy: cannot listen on " + self.getHostAddress() + ": " + e.getMessage());
                reportedFailure = true;
            }
        }
    }

    private static boolean sameAddress(InterfaceAddress a, InterfaceAddress b) {
        if (a == null || b == null) return a == b;
        return Objects.equals(a.getAddress(), b.getAddress())
                && a.getNetworkPrefixLength() == b.getNetworkPrefixLength();
    }

    private static InterfaceAddress findVmAddress() {
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!ni.getName().startsWith(VM_INTERFACE_PREFIX) || !ni.isUp()) continue;
                for (InterfaceAddress a : ni.getInterfaceAddresses()) {
                    if (a.getAddress() instanceof Inet4Address) return a;
                }
            }
        } catch (SocketException e) {
            // treated as no VM for now; the next scan tries again
        }
        return null;
    }

    static boolean inSubnet(InetAddress peer, InetAddress self, int prefix) {
        if (!(peer instanceof Inet4Address)) return false;
        byte[] p = peer.getAddress();
        byte[] s = self.getAddress();
        for (int bit = 0; bit < prefix; bit++) {
            int mask = 0x80 >> (bit % 8);
            if ((p[bit / 8] & mask) != (s[bit / 8] & mask)) return false;
        }
        return true;
    }

    /** Lookups and sockets are bound to the VPN network, so they fail if it is gone. */
    private Socket dial(String host, int port, int timeoutMs) throws IOException {
        Network vpn = vpnNetwork();
        List<InetAddress> addresses = new ArrayList<>();
        // IPv6 is claimed by the tunnel and dropped, so only IPv4 can get anywhere.
        for (InetAddress a : vpn.getAllByName(host)) {
            if (a instanceof Inet4Address) addresses.add(a);
        }
        if (addresses.isEmpty()) throw new UnknownHostException(host);
        IOException last = null;
        for (InetAddress a : addresses) {
            Socket s = new Socket();
            try {
                vpn.bindSocket(s);
                s.connect(new InetSocketAddress(a, port), timeoutMs);
                return s;
            } catch (IOException e) {
                s.close();
                last = e;
            }
        }
        throw last;
    }

    private Network vpnNetwork() throws SocksServer.TunnelDownException {
        if (VpnState.state() != Engine.State.CONNECTED) throw new SocksServer.TunnelDownException();
        Network n = cm.getActiveNetwork();
        NetworkCapabilities caps = n == null ? null : cm.getNetworkCapabilities(n);
        if (caps == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            throw new SocksServer.TunnelDownException();
        }
        return n;
    }
}
