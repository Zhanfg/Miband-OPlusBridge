// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.notify;

import java.util.LinkedHashMap;
import java.util.Iterator;
import java.util.Map;
import nodomain.freeyourgadget.gadgetbridge.proto.xiaomi.XiaomiProto;

/** Collapses the health hook and the local listener posting one notification twice. */
public final class NotifyDedupe {
    public static final long WINDOW_MS = 2_000;
    /** Insertion order lets expiration stop at the first live entry: amortized O(1). */
    private final Map<String, Long> seen = new LinkedHashMap<>();

    public static String identity(XiaomiProto.Command command) {
        if (command == null || !command.hasNotification()) return "";
        var notification = command.getNotification();
        if (notification.hasNotification2() && notification.getNotification2().hasNotification3()) {
            var item = notification.getNotification2().getNotification3();
            return "post\n" + item.getPackage() + "\n" + item.getKey()
                    + "\n" + item.getTitle() + "\n" + item.getBody();
        }
        if (notification.hasNotificationDismiss() && notification.getNotificationDismiss().getNotificationIdCount() > 0) {
            var id = notification.getNotificationDismiss().getNotificationId(0);
            return "dismiss\n" + id.getPackage() + "\n" + id.getKey() + "\n" + id.getId();
        }
        return "";
    }

    /** A different title or body is a new notification, even on the same key. */
    public synchronized boolean first(String identity, long now) {
        if (identity == null || identity.isBlank()) return true;
        Iterator<Map.Entry<String, Long>> entries = seen.entrySet().iterator();
        while (entries.hasNext()) {
            Map.Entry<String, Long> entry = entries.next();
            if (now - entry.getValue() <= WINDOW_MS) break;
            entries.remove();
        }
        Long previous = seen.get(identity);
        if (previous != null && now - previous <= WINDOW_MS) return false;
        seen.put(identity, now);
        return true;
    }
}
