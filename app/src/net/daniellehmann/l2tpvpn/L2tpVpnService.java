package net.daniellehmann.l2tpvpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.VpnService;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;

import net.daniellehmann.l2tpvpn.core.Config;
import net.daniellehmann.l2tpvpn.core.Engine;
import net.daniellehmann.l2tpvpn.core.Platform;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.Objects;

/** Hosts the {@link Engine} inside Android's VpnService and keeps it in the foreground. */
public final class L2tpVpnService extends VpnService implements Platform {
    public static final String ACTION_CONNECT = "net.daniellehmann.l2tpvpn.CONNECT";
    public static final String ACTION_DISCONNECT = "net.daniellehmann.l2tpvpn.DISCONNECT";
    private static final String CHANNEL = "vpn";
    private static final int NOTIFICATION_ID = 1;

    private final Handler main = new Handler(Looper.getMainLooper());
    private Engine engine;
    private Config config;
    private VmProxy vmProxy;
    private ConnectivityManager cm;
    private volatile Network network;
    private LinkProperties linkProps;
    private boolean networkSeen;
    private final Runnable lostCheck = () -> {
        if (network == null && engine != null) engine.onNetworkChanged(false);
    };
    private final Runnable statsTick = new Runnable() {
        @Override public void run() {
            if (engine != null && VpnState.state() == Engine.State.CONNECTED) {
                updateNotification();
                main.postDelayed(this, 5000);
            }
        }
    };

    public static void connect(Context c) {
        c.startForegroundService(new Intent(c, L2tpVpnService.class).setAction(ACTION_CONNECT));
    }

    public static void disconnect(Context c) {
        c.startService(new Intent(c, L2tpVpnService.class).setAction(ACTION_DISCONNECT));
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        if (ACTION_DISCONNECT.equals(action)) {
            shutdown("disconnected");
            return START_NOT_STICKY;
        }
        // ACTION_CONNECT from the UI, or android.net.VpnService from always-on.
        goForeground();
        if (engine != null) return START_STICKY;
        if (!ProfileStore.exists(this)) {
            VpnState.log("no VPN profile configured");
            shutdown("not configured");
            return START_NOT_STICKY;
        }
        config = ProfileStore.load(this);
        String err = config.validate();
        if (err != null) {
            VpnState.log(err);
            VpnState.set(Engine.State.FAILED, err);
            shutdown(null);
            return START_NOT_STICKY;
        }
        VpnState.log("starting VPN to " + config.server);
        registerNetworkCallback();
        engine = new Engine(config, this);
        engine.start();
        if (config.vmProxy) {
            vmProxy = new VmProxy(cm);
            vmProxy.start();
        }
        return START_STICKY;
    }

    private void goForeground() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm.getNotificationChannel(CHANNEL) == null) {
            NotificationChannel ch = new NotificationChannel(CHANNEL, "VPN status", NotificationManager.IMPORTANCE_LOW);
            ch.setShowBadge(false);
            nm.createNotificationChannel(ch);
        }
        startForeground(NOTIFICATION_ID, buildNotification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
    }

    private Notification buildNotification() {
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class),
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        PendingIntent stop = PendingIntent.getService(this, 1,
                new Intent(this, L2tpVpnService.class).setAction(ACTION_DISCONNECT),
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Engine.State s = VpnState.state();
        String title = MainActivity.describe(s);
        String text = VpnState.detail();
        if (s == Engine.State.CONNECTED && engine != null) text = text + " · " + engine.statistics();
        return new Notification.Builder(this, CHANNEL)
                .setSmallIcon(R.drawable.ic_vpn)
                .setContentTitle(title)
                .setContentText(text)
                .setContentIntent(open)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setCategory(Notification.CATEGORY_SERVICE)
                .addAction(new Notification.Action.Builder(null, "Disconnect", stop).build())
                .build();
    }

    private void updateNotification() {
        if (engine == null) return;
        getSystemService(NotificationManager.class).notify(NOTIFICATION_ID, buildNotification());
    }

    private void shutdown(String why) {
        main.removeCallbacks(statsTick);
        main.removeCallbacks(lostCheck);
        if (vmProxy != null) {
            vmProxy.stop();
            vmProxy = null;
        }
        unregisterNetworkCallback();
        Engine e = engine;
        engine = null;
        if (e != null) {
            // Engine.stop sends delete notifications and waits briefly; keep it off the main thread.
            new Thread(e::stop, "l2tp-stop").start();
        } else if (why != null) {
            VpnState.set(Engine.State.DISCONNECTED, "");
        }
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    @Override
    public void onRevoke() {
        VpnState.log("VPN permission revoked by the system or another VPN app");
        shutdown("revoked");
    }

    @Override
    public void onDestroy() {
        if (engine != null) shutdown("destroyed");
        super.onDestroy();
    }

    // ------------------------------------------------------------------ underlying network tracking

    private final ConnectivityManager.NetworkCallback netCallback = new ConnectivityManager.NetworkCallback() {
        @Override public void onAvailable(Network n) {
            main.post(() -> {
                main.removeCallbacks(lostCheck);
                if (n.equals(network)) return;
                boolean first = !networkSeen;
                networkSeen = true;
                network = n;
                linkProps = cm.getLinkProperties(n);
                setUnderlyingNetworks(new Network[] {n});
                // The engine started on whatever network was default; only the
                // first report is not a change.
                if (engine != null && (!first || VpnState.state() == Engine.State.WAITING_FOR_NETWORK)) {
                    engine.onNetworkChanged(true);
                }
            });
        }

        @Override public void onLinkPropertiesChanged(Network n, LinkProperties lp) {
            main.post(() -> {
                if (!n.equals(network)) return;
                LinkProperties old = linkProps;
                linkProps = lp;
                if (old != null && !Objects.equals(ipv4Of(old), ipv4Of(lp)) && engine != null) {
                    VpnState.log("local address changed on the current network");
                    engine.onNetworkChanged(true);
                }
            });
        }

        @Override public void onLost(Network n) {
            main.post(() -> {
                if (!n.equals(network)) return;
                network = null;
                setUnderlyingNetworks(null);
                // A replacement network usually arrives within moments.
                main.postDelayed(lostCheck, 2000);
            });
        }
    };

    private static String ipv4Of(LinkProperties lp) {
        StringBuilder sb = new StringBuilder();
        for (android.net.LinkAddress a : lp.getLinkAddresses()) {
            if (a.getAddress() instanceof Inet4Address) sb.append(a.getAddress().getHostAddress()).append(',');
        }
        return sb.toString();
    }

    private void registerNetworkCallback() {
        cm = getSystemService(ConnectivityManager.class);
        NetworkRequest req = new NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build();
        cm.registerBestMatchingNetworkCallback(req, netCallback, main);
    }

    private void unregisterNetworkCallback() {
        if (cm == null) return;
        try {
            cm.unregisterNetworkCallback(netCallback);
        } catch (IllegalArgumentException ignored) {
            // not registered
        }
        cm = null;
        network = null;
        networkSeen = false;
    }

    // ------------------------------------------------------------------ Platform

    @Override
    public InetAddress resolve(String host) throws IOException {
        Network n = network;
        InetAddress[] all = n != null ? n.getAllByName(host) : InetAddress.getAllByName(host);
        for (InetAddress a : all) if (a instanceof Inet4Address) return a;
        throw new IOException("no IPv4 address for " + host);
    }

    @Override
    public DatagramSocket openSocket() throws IOException {
        DatagramSocket s = new DatagramSocket();
        if (!protect(s)) {
            s.close();
            throw new IOException("cannot protect socket from VPN routing");
        }
        // Deliberately not bound to a specific Network: protected sockets follow the
        // current default route, which also reaches servers on local-only links.
        // Network changes trigger a reconnect with a fresh socket anyway.
        return s;
    }

    @Override
    public Tun establish(TunSettings ts) throws IOException {
        Builder b = new Builder()
                .setSession(config.server)
                .setMtu(ts.mtu)
                .addAddress(InetAddress.getByAddress(ts.address), 32)
                .addRoute("0.0.0.0", 0)
                // Claim IPv6 too so it cannot leak around a v4-only tunnel.
                .addAddress("fd8a:6c32:7470::1", 128)
                .addRoute("::", 0)
                .setMetered(false)
                .setBlocking(false)
                .setConfigureIntent(PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class),
                        PendingIntent.FLAG_IMMUTABLE));
        for (byte[] d : ts.dns) b.addDnsServer(InetAddress.getByAddress(d));
        // This app stays inside its own tunnel so the VM proxy can use it. The sockets that
        // carry the tunnel use protect(), and resolve() names the underlying network.
        Network n = network;
        if (n != null) b.setUnderlyingNetworks(new Network[] {n});
        ParcelFileDescriptor pfd = b.establish();
        if (pfd == null) return null;
        try {
            return new AndroidTun(pfd);
        } catch (ErrnoException e) {
            pfd.close();
            throw new IOException(e);
        }
    }

    @Override
    public void log(String line) {
        VpnState.log(line);
    }

    @Override
    public void onStatus(Engine.State state, String detail) {
        VpnState.set(state, detail);
        main.post(() -> {
            if (state == Engine.State.FAILED || state == Engine.State.DISCONNECTED) {
                if (engine != null) shutdown(null);
                return;
            }
            updateNotification();
            if (state == Engine.State.CONNECTED) {
                main.removeCallbacks(statsTick);
                main.postDelayed(statsTick, 5000);
            }
        });
    }

    /** TUN fd wrapper: poll() on the fd plus a wake-up pipe so close() never hangs a reader. */
    private static final class AndroidTun implements Tun {
        private final ParcelFileDescriptor pfd;
        private final FileDescriptor fd;
        private final FileDescriptor wakeR, wakeW;
        private volatile boolean closed;

        AndroidTun(ParcelFileDescriptor pfd) throws ErrnoException {
            this.pfd = pfd;
            this.fd = pfd.getFileDescriptor();
            FileDescriptor[] pipe = Os.pipe();
            wakeR = pipe[0];
            wakeW = pipe[1];
        }

        @Override
        public int read(byte[] buf, int off, int len) throws IOException {
            StructPollfd tunPoll = new StructPollfd();
            tunPoll.fd = fd;
            tunPoll.events = (short) OsConstants.POLLIN;
            StructPollfd wakePoll = new StructPollfd();
            wakePoll.fd = wakeR;
            wakePoll.events = (short) OsConstants.POLLIN;
            StructPollfd[] fds = {tunPoll, wakePoll};
            while (!closed) {
                try {
                    int n = Os.read(fd, buf, off, len);
                    if (n > 0) return n;
                } catch (ErrnoException e) {
                    if (e.errno != OsConstants.EAGAIN && e.errno != OsConstants.EINTR) {
                        if (closed) return -1;
                        throw new IOException(e);
                    }
                } catch (InterruptedIOException e) {
                    return -1;
                }
                try {
                    Os.poll(fds, -1);
                } catch (ErrnoException e) {
                    if (e.errno != OsConstants.EINTR) throw new IOException(e);
                }
                if ((wakePoll.revents & OsConstants.POLLIN) != 0 || (tunPoll.revents & OsConstants.POLLNVAL) != 0) {
                    return -1;
                }
            }
            return -1;
        }

        @Override
        public void write(byte[] buf, int off, int len) throws IOException {
            try {
                Os.write(fd, buf, off, len);
            } catch (ErrnoException e) {
                if (e.errno == OsConstants.EAGAIN) return;  // queue full: drop like a router would
                throw new IOException(e);
            } catch (InterruptedIOException e) {
                // dropped
            }
        }

        @Override
        public void close() {
            if (closed) return;
            closed = true;
            try {
                Os.write(wakeW, new byte[1], 0, 1);
            } catch (ErrnoException | InterruptedIOException ignored) {
                // reader will notice the closed fd instead
            }
            // Let the reader observe the wake-up before the fds disappear.
            new Handler(Looper.getMainLooper()).postDelayed(() -> {
                try {
                    pfd.close();
                } catch (IOException ignored) {
                    // already closed
                }
                try {
                    Os.close(wakeR);
                    Os.close(wakeW);
                } catch (ErrnoException ignored) {
                    // already closed
                }
            }, 500);
        }
    }
}
