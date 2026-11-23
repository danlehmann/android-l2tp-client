package net.daniellehmann.l2tpvpn;

import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;

import net.daniellehmann.l2tpvpn.core.Engine;

/** Quick Settings tile that toggles the VPN. */
public final class ToggleTileService extends TileService implements VpnState.Listener {
    @Override
    public void onStartListening() {
        VpnState.addListener(this);
        onChanged();
    }

    @Override
    public void onStopListening() {
        VpnState.removeListener(this);
    }

    @Override
    public void onClick() {
        if (VpnState.isActive()) {
            L2tpVpnService.disconnect(this);
        } else if (VpnService.prepare(this) != null || !ProfileStore.exists(this)) {
            // First run needs the consent dialog / a profile: open the app.
            Intent i = new Intent(this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, i, PendingIntent.FLAG_IMMUTABLE));
        } else {
            VpnState.set(Engine.State.CONNECTING, "");
            L2tpVpnService.connect(this);
        }
    }

    @Override
    public void onChanged() {
        Tile t = getQsTile();
        if (t == null) return;
        Engine.State s = VpnState.state();
        t.setState(VpnState.isActive() ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE);
        t.setLabel("L2TP VPN");
        t.setSubtitle(MainActivity.describe(s));
        t.updateTile();
    }
}
