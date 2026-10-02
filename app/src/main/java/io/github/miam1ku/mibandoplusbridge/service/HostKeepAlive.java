// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.service;

import android.content.Context;

/**
 * Event wake facade. Root shell/process launching has been removed.
 *
 * Bridge wake attempts are ordinary Android service starts; when background
 * start is restricted, CompanionPresence is the system-owned recovery path.
 */
public final class HostKeepAlive {
    private HostKeepAlive() {}

    /** Notification, music, device-card or companion-presence event. */
    public static void ensureBridge(Context context) {
        if (context == null) return;
        BandLiveService.ensureProcess(context);
    }
}
