// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.service;

import android.companion.CompanionDeviceService;
import android.companion.DevicePresenceEvent;
import io.github.miam1ku.mibandoplusbridge.data.SessionLog;

/** System-bound only while the associated Xiaomi band is nearby or connected. */
public final class BandCompanionService extends CompanionDeviceService {
    @Override public void onDevicePresenceEvent(DevicePresenceEvent event) {
        if (event == null || !CompanionPresence.matches(this, event.getAssociationId())) return;
        int kind = event.getEvent();
        SessionLog.line(this, "COMPANION_PRESENCE event=" + kind + " association=" + event.getAssociationId());
        if (kind == DevicePresenceEvent.EVENT_BLE_APPEARED
                || kind == DevicePresenceEvent.EVENT_BT_CONNECTED) {
            HostKeepAlive.ensureBridge(this);
        }
        // Do not stop the live link on DISAPPEARED/DISCONNECTED. Radio presence can
        // flap briefly and the session supervisor already owns reconnect/backoff.
    }
}
