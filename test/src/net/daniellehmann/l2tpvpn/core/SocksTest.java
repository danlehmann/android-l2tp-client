package net.daniellehmann.l2tpvpn.core;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** Exercises {@link SocksServer} over loopback with a fake dialer. */
public final class SocksTest {
    private static final InetAddress LO = InetAddress.getLoopbackAddress();
    private static int failures;

    public static void main(String[] args) throws Exception {
        // Reads until EOF, then writes back the upper-cased data: only works if half-close survives.
        ServerSocket upper = new ServerSocket(0, 50, LO);
        Thread t = new Thread(() -> {
            while (true) {
                try {
                    Socket s = upper.accept();
                    Thread h = new Thread(() -> {
                        try (Socket c = s) {
                            byte[] all = readAll(c.getInputStream());
                            c.getOutputStream().write(new String(all, StandardCharsets.ISO_8859_1)
                                    .toUpperCase().getBytes(StandardCharsets.ISO_8859_1));
                        } catch (IOException ignored) {
                            // the test notices
                        }
                    });
                    h.start();
                } catch (IOException e) {
                    return;
                }
            }
        });
        t.setDaemon(true);
        t.start();

        AtomicBoolean tunnelUp = new AtomicBoolean(true);
        List<String> dialed = Collections.synchronizedList(new ArrayList<>());
        SocksServer.Dialer dialer = (host, port, timeout) -> {
            dialed.add(host + ":" + port);
            if (!tunnelUp.get()) throw new SocksServer.TunnelDownException();
            if (host.equals("nxdomain.test")) throw new UnknownHostException(host);
            if (port == 9) throw new ConnectException("refused");
            Socket s = new Socket();
            s.connect(new InetSocketAddress(LO, upper.getLocalPort()), timeout);
            return s;
        };
        AtomicBoolean allow = new AtomicBoolean(true);
        SocksServer srv = new SocksServer(LO, 0, dialer, a -> allow.get(), l -> { });
        int port = srv.port();
        int up = upper.getLocalPort();

        try (Socket c = open(port)) {
            check("domain CONNECT succeeds", connectDomain(c, "host.test", up) == 0);
            check("domain is passed to the dialer unresolved", dialed.contains("host.test:" + up));
            c.getOutputStream().write("hello".getBytes(StandardCharsets.US_ASCII));
            c.shutdownOutput();
            check("data relays both ways across half-close",
                    new String(readAll(c.getInputStream()), StandardCharsets.US_ASCII).equals("HELLO"));
        }

        try (Socket c = open(port)) {
            negotiate(c);
            c.getOutputStream().write(new byte[] {5, 1, 0, 1, 127, 0, 0, 1, (byte) (up >> 8), (byte) up});
            check("IPv4 CONNECT succeeds", readReply(c) == 0 && dialed.contains("127.0.0.1:" + up));
        }

        try (Socket c = open(port)) {
            check("unknown host gives host unreachable", connectDomain(c, "nxdomain.test", 80) == 4);
        }
        try (Socket c = open(port)) {
            check("refused gives connection refused", connectDomain(c, "host.test", 9) == 5);
        }
        tunnelUp.set(false);
        try (Socket c = open(port)) {
            check("tunnel down gives network unreachable", connectDomain(c, "host.test", 80) == 3);
        }
        tunnelUp.set(true);

        try (Socket c = open(port)) {
            negotiate(c);
            dialed.clear();
            c.getOutputStream().write(new byte[] {5, 3, 0, 1, 127, 0, 0, 1, 0, 53});  // UDP ASSOCIATE
            check("UDP ASSOCIATE is refused", readReply(c) == 7 && dialed.isEmpty());
        }
        try (Socket c = open(port)) {
            c.getOutputStream().write(new byte[] {5, 1, 2});  // username/password only
            DataInputStream in = new DataInputStream(c.getInputStream());
            check("no common auth method is refused", in.readUnsignedByte() == 5 && in.readUnsignedByte() == 0xFF);
        }
        try (Socket c = open(port)) {
            c.getOutputStream().write("GET / HTTP/1.1\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            check("non-SOCKS client is dropped", c.getInputStream().read() == -1);
        }

        allow.set(false);
        dialed.clear();
        try (Socket c = open(port)) {
            c.getOutputStream().write(new byte[] {5, 1, 0});
            check("disallowed peer is dropped", readClosed(c) && dialed.isEmpty());
        }
        allow.set(true);

        AtomicInteger bytes = new AtomicInteger();
        Socket live = open(port);
        check("connection opens before stop", connectDomain(live, "host.test", up) == 0);
        srv.stop();
        try {
            bytes.set(live.getInputStream().read());
        } catch (IOException e) {
            bytes.set(-1);
        }
        check("stop() drops live connections", bytes.get() == -1);
        live.close();
        boolean refused = false;
        try (Socket c = open(port)) {
            refused = c.getInputStream().read() == -1;
        } catch (IOException e) {
            refused = true;
        }
        check("stop() stops listening", refused);

        System.out.println(failures == 0 ? "ALL PASSED" : failures + " FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    private static Socket open(int port) throws IOException {
        Socket s = new Socket(LO, port);
        s.setSoTimeout(5000);
        return s;
    }

    private static void negotiate(Socket c) throws IOException {
        c.getOutputStream().write(new byte[] {5, 1, 0});
        DataInputStream in = new DataInputStream(c.getInputStream());
        if (in.readUnsignedByte() != 5 || in.readUnsignedByte() != 0) throw new IOException("bad method reply");
    }

    private static int connectDomain(Socket c, String host, int port) throws IOException {
        negotiate(c);
        byte[] name = host.getBytes(StandardCharsets.US_ASCII);
        OutputStream out = c.getOutputStream();
        out.write(new byte[] {5, 1, 0, 3, (byte) name.length});
        out.write(name);
        out.write(new byte[] {(byte) (port >> 8), (byte) port});
        return readReply(c);
    }

    private static int readReply(Socket c) throws IOException {
        byte[] r = new byte[10];
        new DataInputStream(c.getInputStream()).readFully(r);
        return r[1] & 0xFF;
    }

    private static boolean readClosed(Socket c) {
        try {
            return c.getInputStream().read() == -1;
        } catch (IOException e) {
            return true;
        }
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) >= 0) b.write(buf, 0, n);
        return b.toByteArray();
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "PASS " : "FAIL ") + name);
        if (!ok) failures++;
    }
}
