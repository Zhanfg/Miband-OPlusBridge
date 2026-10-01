// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.service;

import android.app.Activity;
import android.companion.AssociationInfo;
import android.companion.AssociationRequest;
import android.companion.BluetoothDeviceFilter;
import android.companion.CompanionDeviceManager;
import android.companion.ObservingDevicePresenceRequest;
import android.content.Context;
import android.content.IntentSender;
import android.content.pm.PackageManager;
import io.github.miam1ku.mibandoplusbridge.data.BindingStore;
import io.github.miam1ku.mibandoplusbridge.data.SessionLog;
import java.util.List;

/**
 * System-owned companion presence for the registered band.
 *
 * Presence observation is the primary wake path on API 36. It lets Android bind
 * {@link BandCompanionService} only while the band is nearby/connected, so the
 * bridge does not need a polling watchdog just to discover that the band returned.
 */
public final class CompanionPresence {
    public static final int NO_ASSOCIATION = -1;
    public static final int ASSOCIATION_REQUEST = 7301;

    public interface Listener {
        void onPending();
        void onAssociated();
        void onFailure(String reason);
    }

    private CompanionPresence() {}

    public static boolean supported(Context context) {
        return context != null && context.getPackageManager().hasSystemFeature(
                PackageManager.FEATURE_COMPANION_DEVICE_SETUP);
    }

    public static int associationId(Context context) {
        if (!supported(context)) return NO_ASSOCIATION;
        String address = boundAddress(context);
        if (address.isBlank()) return NO_ASSOCIATION;
        CompanionDeviceManager manager = context.getSystemService(CompanionDeviceManager.class);
        if (manager == null) return NO_ASSOCIATION;
        try {
            List<AssociationInfo> associations = manager.getMyAssociations();
            for (AssociationInfo association : associations) {
                if (association == null || association.getDeviceMacAddress() == null) continue;
                if (address.equalsIgnoreCase(association.getDeviceMacAddress().toString())) {
                    return association.getId();
                }
            }
        } catch (RuntimeException unavailable) {
            SessionLog.line(context, "COMPANION_ASSOCIATION_READ_FAILED "
                    + unavailable.getClass().getSimpleName());
        }
        return NO_ASSOCIATION;
    }

    public static boolean matches(Context context, int associationId) {
        return associationId >= 0 && associationId(context) == associationId;
    }

    /** Idempotent: Android de-duplicates observation for the same association. */
    public static boolean ensureObserving(Context context) {
        if (context == null || !supported(context)) return false;
        int associationId = associationId(context);
        if (associationId < 0) return false;
        CompanionDeviceManager manager = context.getSystemService(CompanionDeviceManager.class);
        if (manager == null) return false;
        try {
            manager.startObservingDevicePresence(new ObservingDevicePresenceRequest.Builder()
                    .setAssociationId(associationId).build());
            context.getSharedPreferences("companion-presence", Context.MODE_PRIVATE).edit()
                    .putInt("associationId", associationId).apply();
            return true;
        } catch (RuntimeException unavailable) {
            SessionLog.line(context, "COMPANION_OBSERVE_FAILED " + unavailable.getClass().getSimpleName());
            return false;
        }
    }

    /**
     * Requests one exact-MAC watch association. The platform owns discovery and
     * confirmation UI; this method never creates a silent/self-managed association.
     */
    public static void requestAssociation(Activity activity, Listener listener) {
        if (activity == null || listener == null) return;
        if (!supported(activity)) {
            listener.onFailure("COMPANION_DEVICE_UNSUPPORTED");
            return;
        }
        String address = boundAddress(activity);
        if (address.isBlank()) {
            listener.onFailure("BINDING_REQUIRED");
            return;
        }
        if (associationId(activity) >= 0) {
            ensureObserving(activity);
            listener.onAssociated();
            return;
        }
        CompanionDeviceManager manager = activity.getSystemService(CompanionDeviceManager.class);
        if (manager == null) {
            listener.onFailure("COMPANION_DEVICE_UNAVAILABLE");
            return;
        }
        AssociationRequest request = new AssociationRequest.Builder()
                .addDeviceFilter(new BluetoothDeviceFilter.Builder().setAddress(address).build())
                .setSingleDevice(true)
                .setDeviceProfile(AssociationRequest.DEVICE_PROFILE_WATCH)
                .build();
        try {
            manager.associate(request, activity.getMainExecutor(), new CompanionDeviceManager.Callback() {
                @Override public void onAssociationPending(IntentSender intentSender) {
                    listener.onPending();
                    try {
                        activity.startIntentSenderForResult(intentSender, ASSOCIATION_REQUEST,
                                null, 0, 0, 0);
                    } catch (IntentSender.SendIntentException failure) {
                        listener.onFailure("COMPANION_CONFIRMATION_FAILED");
                    }
                }

                @Override public void onAssociationCreated(AssociationInfo associationInfo) {
                    if (associationInfo == null || associationInfo.getDeviceMacAddress() == null
                            || !address.equalsIgnoreCase(associationInfo.getDeviceMacAddress().toString())) {
                        listener.onFailure("COMPANION_IDENTITY_MISMATCH");
                        return;
                    }
                    ensureObserving(activity);
                    listener.onAssociated();
                }

                @Override public void onFailure(CharSequence error) {
                    listener.onFailure(error == null || error.toString().isBlank()
                            ? "COMPANION_ASSOCIATION_FAILED" : error.toString());
                }
            });
        } catch (RuntimeException failure) {
            listener.onFailure("COMPANION_ASSOCIATION_FAILED");
        }
    }

    private static String boundAddress(Context context) {
        try {
            BindingStore.Identity identity = new BindingStore(context).readIdentity();
            return identity == null || identity.address() == null ? "" : identity.address();
        } catch (Exception unavailable) {
            return "";
        }
    }
}
