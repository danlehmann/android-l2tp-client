package net.daniellehmann.l2tpvpn;

import android.os.Handler;
import android.os.Looper;

import net.daniellehmann.l2tpvpn.core.Engine;

import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/** Process-wide connection status and log ring buffer, observed by the UI and the tile. */
public final class VpnState {
    public interface Listener {
        void onChanged();
    }

    private static final int MAX_LINES = 1000;
    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static final List<Listener> LISTENERS = new ArrayList<>();
    private static final ArrayDeque<String> LOG = new ArrayDeque<>();
    private static final SimpleDateFormat TS = new SimpleDateFormat("HH:mm:ss.SSS", Locale.US);

    private static volatile Engine.State state = Engine.State.DISCONNECTED;
    private static volatile String detail = "";
    private static volatile long since = System.currentTimeMillis();
    private static boolean notifyPending;

    private VpnState() {}

    public static Engine.State state() {
        return state;
    }

    public static String detail() {
        return detail;
    }

    public static long since() {
        return since;
    }

    public static boolean isActive() {
        Engine.State s = state;
        return s != Engine.State.DISCONNECTED && s != Engine.State.FAILED;
    }

    public static void set(Engine.State s, String d) {
        if (s != state) since = System.currentTimeMillis();
        state = s;
        detail = d == null ? "" : d;
        changed();
    }

    public static void log(String line) {
        String stamped;
        synchronized (TS) {
            stamped = TS.format(new Date()) + "  " + line;
        }
        synchronized (LOG) {
            LOG.addLast(stamped);
            while (LOG.size() > MAX_LINES) LOG.removeFirst();
        }
        changed();
    }

    public static String logText() {
        synchronized (LOG) {
            StringBuilder sb = new StringBuilder();
            for (String l : LOG) sb.append(l).append('\n');
            return sb.toString();
        }
    }

    public static void clearLog() {
        synchronized (LOG) {
            LOG.clear();
        }
        changed();
    }

    /** Coalesces bursts of updates into one main-thread callback. */
    private static void changed() {
        synchronized (LISTENERS) {
            if (notifyPending) return;
            notifyPending = true;
        }
        MAIN.postDelayed(() -> {
            List<Listener> copy;
            synchronized (LISTENERS) {
                notifyPending = false;
                copy = new ArrayList<>(LISTENERS);
            }
            for (Listener l : copy) l.onChanged();
        }, 100);
    }

    public static void addListener(Listener l) {
        synchronized (LISTENERS) {
            LISTENERS.add(l);
        }
    }

    public static void removeListener(Listener l) {
        synchronized (LISTENERS) {
            LISTENERS.remove(l);
        }
    }
}
