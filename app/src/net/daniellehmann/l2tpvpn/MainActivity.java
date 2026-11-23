package net.daniellehmann.l2tpvpn;

import android.Manifest;
import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Insets;
import android.graphics.Typeface;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.text.InputType;
import android.text.format.DateUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import net.daniellehmann.l2tpvpn.core.Config;
import net.daniellehmann.l2tpvpn.core.Engine;

/** Single screen: profile fields, connect button, status and log. */
public final class MainActivity extends Activity implements VpnState.Listener {
    private static final int REQ_VPN = 1;

    private EditText server, psk, username, password, dns, mtu;
    private CheckBox vmProxy;
    private TextView status, detail, log;
    private Button connect;
    private ScrollView scroll;

    public static String describe(Engine.State s) {
        switch (s) {
            case CONNECTING: return "Connecting…";
            case CONNECTED: return "Connected";
            case RECONNECTING: return "Reconnecting…";
            case WAITING_FOR_NETWORK: return "Waiting for network";
            case FAILED: return "Connection failed";
            default: return "Disconnected";
        }
    }

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        setTitle("L2TP VPN");
        scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(16);
        root.setPadding(pad, pad, pad, pad);
        scroll.addView(root);
        scroll.setOnApplyWindowInsetsListener((v, insets) -> {
            Insets i = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.ime()
                    | WindowInsets.Type.displayCutout());
            v.setPadding(i.left, i.top, i.right, i.bottom);
            return WindowInsets.CONSUMED;
        });

        status = new TextView(this);
        status.setTextSize(TypedValue.COMPLEX_UNIT_SP, 24);
        status.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(status);
        detail = new TextView(this);
        detail.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        detail.setPadding(0, dp(4), 0, dp(12));
        root.addView(detail);

        connect = new Button(this);
        connect.setOnClickListener(v -> onConnectClicked());
        root.addView(connect, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(56)));

        root.addView(header("Profile"));
        server = field(root, "Server (hostname or IP)", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        psk = field(root, "IPsec pre-shared key", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        username = field(root, "Username", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        password = field(root, "Password", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        CheckBox show = new CheckBox(this);
        show.setText("Show secrets");
        show.setOnCheckedChangeListener((b, on) -> {
            int t = InputType.TYPE_CLASS_TEXT | (on ? InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                    : InputType.TYPE_TEXT_VARIATION_PASSWORD);
            psk.setInputType(t);
            password.setInputType(t);
        });
        root.addView(show);
        root.addView(header("Advanced (optional)"));
        dns = field(root, "DNS servers, e.g. 10.0.0.1 (default: from server)", InputType.TYPE_CLASS_TEXT);
        mtu = field(root, "MTU (default: automatic)", InputType.TYPE_CLASS_NUMBER);
        vmProxy = new CheckBox(this);
        vmProxy.setText("Share with the Linux VM (SOCKS5 proxy on port " + VmProxy.PORT + ", TCP only). "
                + "Reachable from the VM only.");
        root.addView(vmProxy);

        TextView note = new TextView(this);
        note.setText("Tip: Settings › Network › VPN › ⚙ › \"Always-on VPN\" and \"Block connections without VPN\" "
                + "keep you connected and stop leaks. This app has no analytics and only talks to your VPN server.");
        note.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        note.setPadding(0, dp(12), 0, 0);
        root.addView(note);

        LinearLayout logBar = new LinearLayout(this);
        logBar.setOrientation(LinearLayout.HORIZONTAL);
        logBar.setGravity(Gravity.CENTER_VERTICAL);
        TextView logHeader = header("Log");
        logBar.addView(logHeader, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        Button copy = new Button(this);
        copy.setText("Copy");
        copy.setOnClickListener(v -> {
            getSystemService(ClipboardManager.class).setPrimaryClip(ClipData.newPlainText("VPN log", VpnState.logText()));
            Toast.makeText(this, "Log copied", Toast.LENGTH_SHORT).show();
        });
        logBar.addView(copy);
        Button clear = new Button(this);
        clear.setText("Clear");
        clear.setOnClickListener(v -> VpnState.clearLog());
        logBar.addView(clear);
        root.addView(logBar);

        log = new TextView(this);
        log.setTypeface(Typeface.MONOSPACE);
        log.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        log.setTextIsSelectable(true);
        root.addView(log);

        setContentView(scroll);
        loadProfile();
    }

    private TextView header(String text) {
        TextView t = new TextView(this);
        t.setText(text);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        t.setTypeface(Typeface.DEFAULT_BOLD);
        t.setPadding(0, dp(20), 0, dp(4));
        return t;
    }

    private EditText field(LinearLayout root, String hint, int type) {
        EditText e = new EditText(this);
        e.setHint(hint);
        // setSingleLine() swaps in its own transformation, so it must come before
        // setInputType() or password fields end up readable.
        e.setSingleLine(true);
        e.setInputType(type);
        e.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
        root.addView(e, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        return e;
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }

    private void loadProfile() {
        if (!ProfileStore.exists(this)) return;
        Config c = ProfileStore.load(this);
        server.setText(c.server);
        psk.setText(c.psk);
        username.setText(c.username);
        password.setText(c.password);
        dns.setText(c.dnsOverride);
        mtu.setText(c.mtu > 0 ? Integer.toString(c.mtu) : "");
        vmProxy.setChecked(c.vmProxy);
    }

    private Config readForm() {
        Config c = new Config();
        c.server = server.getText().toString().trim();
        c.psk = psk.getText().toString();
        c.username = username.getText().toString().trim();
        c.password = password.getText().toString();
        c.dnsOverride = dns.getText().toString().trim();
        c.vmProxy = vmProxy.isChecked();
        try {
            c.mtu = mtu.getText().length() == 0 ? 0 : Integer.parseInt(mtu.getText().toString().trim());
        } catch (NumberFormatException e) {
            c.mtu = -1;
        }
        return c;
    }

    private void onConnectClicked() {
        if (VpnState.isActive()) {
            L2tpVpnService.disconnect(this);
            return;
        }
        Config c = readForm();
        String err = c.validate();
        if (err != null) {
            Toast.makeText(this, err, Toast.LENGTH_LONG).show();
            return;
        }
        ProfileStore.save(this, c);
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[] {Manifest.permission.POST_NOTIFICATIONS}, 2);
        }
        Intent consent = VpnService.prepare(this);
        if (consent != null) {
            startActivityForResult(consent, REQ_VPN);
        } else {
            onActivityResult(REQ_VPN, RESULT_OK, null);
        }
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        if (request != REQ_VPN) return;
        if (result == RESULT_OK) {
            VpnState.set(Engine.State.CONNECTING, "");
            L2tpVpnService.connect(this);
        } else {
            Toast.makeText(this, "VPN permission is required", Toast.LENGTH_LONG).show();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        VpnState.addListener(this);
        onChanged();
    }

    @Override
    protected void onPause() {
        VpnState.removeListener(this);
        super.onPause();
    }

    @Override
    public void onChanged() {
        Engine.State s = VpnState.state();
        status.setText(describe(s));
        String d = VpnState.detail();
        if (s == Engine.State.CONNECTED) {
            d = "Address " + d + " · since "
                    + DateUtils.formatDateTime(this, VpnState.since(), DateUtils.FORMAT_SHOW_TIME);
        }
        detail.setText(d);
        detail.setVisibility(d.isEmpty() ? View.GONE : View.VISIBLE);
        connect.setText(VpnState.isActive() ? "Disconnect" : "Connect");
        boolean editable = !VpnState.isActive();
        for (EditText e : new EditText[] {server, psk, username, password, dns, mtu}) e.setEnabled(editable);
        vmProxy.setEnabled(editable);
        boolean atBottom = !scroll.canScrollVertically(1);
        log.setText(VpnState.logText());
        if (atBottom) scroll.post(() -> scroll.fullScroll(View.FOCUS_DOWN));
    }
}
