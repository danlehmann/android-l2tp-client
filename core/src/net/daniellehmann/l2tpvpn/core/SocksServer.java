package net.daniellehmann.l2tpvpn.core;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NoRouteToHostException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Predicate;

/** Minimal SOCKS5 server (RFC 1928): CONNECT only, no authentication, so peers must be filtered. */
public final class SocksServer {
    /** Opens the outgoing connection. Must fail rather than use a route outside the tunnel. */
    public interface Dialer {
        Socket dial(String host, int port, int timeoutMs) throws IOException;
    }

    /** Thrown by a {@link Dialer} while the tunnel is unavailable. */
    public static final class TunnelDownException extends IOException {
        public TunnelDownException() {
            super("VPN is not connected");
        }
    }

    private static final int VERSION = 5;
    private static final int NO_AUTH = 0;
    private static final int NO_ACCEPTABLE_METHOD = 0xFF;
    private static final int CMD_CONNECT = 1;
    private static final int ATYP_IPV4 = 1;
    private static final int ATYP_DOMAIN = 3;
    private static final int ATYP_IPV6 = 4;
    private static final int REP_OK = 0;
    private static final int REP_FAILURE = 1;
    private static final int REP_NETWORK_UNREACHABLE = 3;
    private static final int REP_HOST_UNREACHABLE = 4;
    private static final int REP_REFUSED = 5;
    private static final int REP_COMMAND_UNSUPPORTED = 7;
    private static final int REP_ATYP_UNSUPPORTED = 8;

    private static final int HANDSHAKE_TIMEOUT_MS = 10_000;
    private static final int CONNECT_TIMEOUT_MS = 20_000;
    private static final int MAX_CONNECTIONS = 256;
    private static final int BUFFER = 16 * 1024;

    private final ServerSocket listener;
    private final Dialer dialer;
    private final Predicate<InetAddress> allowedPeer;
    private final Consumer<String> log;
    private final Set<Socket> open = ConcurrentHashMap.newKeySet();
    private final AtomicInteger connections = new AtomicInteger();
    private volatile boolean stopped;

    public SocksServer(InetAddress bind, int port, Dialer dialer, Predicate<InetAddress> allowedPeer,
            Consumer<String> log) throws IOException {
        this.dialer = dialer;
        this.allowedPeer = allowedPeer;
        this.log = log;
        listener = new ServerSocket();
        listener.setReuseAddress(true);
        listener.bind(new InetSocketAddress(bind, port), 64);
        Thread t = new Thread(this::acceptLoop, "socks-accept");
        t.setDaemon(true);
        t.start();
    }

    public int port() {
        return listener.getLocalPort();
    }

    /** Stops listening and drops every connection in progress. */
    public void stop() {
        stopped = true;
        closeQuietly(listener);
        for (Socket s : open) closeQuietly(s);
    }

    private void acceptLoop() {
        while (!stopped) {
            Socket client;
            try {
                client = listener.accept();
            } catch (IOException e) {
                if (!stopped) log.accept("proxy: stopped listening: " + e.getMessage());
                return;
            }
            if (!allowedPeer.test(client.getInetAddress())) {
                log.accept("proxy: refused a connection from " + client.getInetAddress().getHostAddress());
                closeQuietly(client);
            } else if (connections.incrementAndGet() > MAX_CONNECTIONS) {
                connections.decrementAndGet();
                log.accept("proxy: too many connections");
                closeQuietly(client);
            } else {
                Thread t = new Thread(() -> serve(client), "socks-conn");
                t.setDaemon(true);
                t.start();
            }
        }
    }

    private void serve(Socket client) {
        open.add(client);
        Socket remote = null;
        try {
            if (stopped) return;
            client.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
            client.setTcpNoDelay(true);
            // Unbuffered, so bytes after the request stay in the socket for relaying.
            DataInputStream in = new DataInputStream(client.getInputStream());
            OutputStream out = client.getOutputStream();
            if (!negotiate(in, out)) return;
            String[] host = new String[1];
            int port = readRequest(in, out, host);
            if (port < 0) return;
            try {
                remote = dialer.dial(host[0], port, CONNECT_TIMEOUT_MS);
            } catch (IOException | RuntimeException e) {
                reply(out, replyFor(e));
                return;
            }
            open.add(remote);
            if (stopped) return;
            remote.setTcpNoDelay(true);
            remote.setKeepAlive(true);
            client.setKeepAlive(true);
            reply(out, REP_OK);
            client.setSoTimeout(0);
            relay(client, remote);
            remote = null;  // relay closes both
            client = null;
        } catch (IOException e) {
            // Client went away or stalled during the handshake.
        } finally {
            if (remote != null) release(remote);
            if (client != null) {
                release(client);
                connections.decrementAndGet();
            }
        }
    }

    private static boolean negotiate(DataInputStream in, OutputStream out) throws IOException {
        if (in.readUnsignedByte() != VERSION) return false;
        byte[] methods = new byte[in.readUnsignedByte()];
        in.readFully(methods);
        for (byte m : methods) {
            if (m == NO_AUTH) {
                out.write(new byte[] {VERSION, NO_AUTH});
                return true;
            }
        }
        out.write(new byte[] {VERSION, (byte) NO_ACCEPTABLE_METHOD});
        return false;
    }

    /** Returns the destination port and fills in the host, or returns -1 after replying with an error. */
    private static int readRequest(DataInputStream in, OutputStream out, String[] host) throws IOException {
        if (in.readUnsignedByte() != VERSION) return -1;
        int cmd = in.readUnsignedByte();
        in.readUnsignedByte();  // reserved
        int atyp = in.readUnsignedByte();
        byte[] addr;
        switch (atyp) {
            case ATYP_IPV4:
                addr = new byte[4];
                break;
            case ATYP_IPV6:
                addr = new byte[16];
                break;
            case ATYP_DOMAIN:
                addr = new byte[in.readUnsignedByte()];
                break;
            default:
                reply(out, REP_ATYP_UNSUPPORTED);
                return -1;
        }
        in.readFully(addr);
        int port = in.readUnsignedShort();
        if (cmd != CMD_CONNECT) {
            reply(out, REP_COMMAND_UNSUPPORTED);
            return -1;
        }
        host[0] = atyp == ATYP_DOMAIN
                ? new String(addr, StandardCharsets.US_ASCII)
                : InetAddress.getByAddress(addr).getHostAddress();
        if (host[0].isEmpty()) {
            reply(out, REP_HOST_UNREACHABLE);
            return -1;
        }
        return port;
    }

    private static int replyFor(Exception e) {
        if (e instanceof TunnelDownException) return REP_NETWORK_UNREACHABLE;
        if (e instanceof ConnectException) return REP_REFUSED;
        if (e instanceof UnknownHostException || e instanceof NoRouteToHostException
                || e instanceof SocketTimeoutException) {
            return REP_HOST_UNREACHABLE;
        }
        return REP_FAILURE;
    }

    private static void reply(OutputStream out, int code) throws IOException {
        out.write(new byte[] {VERSION, (byte) code, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0});
    }

    /** Pumps both directions, preserving half-close, and closes both sockets when they finish. */
    private void relay(Socket client, Socket remote) {
        AtomicInteger running = new AtomicInteger(2);
        Runnable done = () -> {
            if (running.decrementAndGet() == 0) {
                release(client);
                release(remote);
                connections.decrementAndGet();
            }
        };
        Thread up = new Thread(() -> pump(client, remote, done), "socks-up");
        up.setDaemon(true);
        up.start();
        pump(remote, client, done);
    }

    private void pump(Socket from, Socket to, Runnable done) {
        byte[] buf = new byte[BUFFER];
        try {
            InputStream in = from.getInputStream();
            OutputStream out = to.getOutputStream();
            int n;
            while ((n = in.read(buf)) >= 0) out.write(buf, 0, n);
            to.shutdownOutput();
        } catch (IOException e) {
            // A reset on either side ends the whole connection.
            closeQuietly(from);
            closeQuietly(to);
        } finally {
            done.run();
        }
    }

    private void release(Socket s) {
        open.remove(s);
        closeQuietly(s);
    }

    private static void closeQuietly(java.io.Closeable c) {
        try {
            c.close();
        } catch (IOException ignored) {
            // nothing useful to do
        }
    }
}
