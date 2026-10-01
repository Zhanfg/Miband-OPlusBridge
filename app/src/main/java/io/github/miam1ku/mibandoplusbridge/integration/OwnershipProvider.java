// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.integration;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.Process;
import io.github.miam1ku.mibandoplusbridge.HostIdentity;
import io.github.miam1ku.mibandoplusbridge.data.LocalPrefs;

/**
 * Minimal ownership IPC used by the module injected into Mi Fitness.
 * It intentionally exposes no authentication token or health payload.
 */
public final class OwnershipProvider extends ContentProvider {
    public static final Uri URI = Uri.parse("content://io.github.miam1ku.mibandoplusbridge.ownership");

    @Override public boolean onCreate() { return true; }

    @Override public Bundle call(String method, String arg, Bundle extras) {
        boolean self = Binder.getCallingUid() == Process.myUid();
        if (!self) HostIdentity.requireMiCaller(getContext());
        if (!"state".equals(method) && !"hookOnline".equals(method)) {
            throw new SecurityException("OWNERSHIP_OPERATION_UNSUPPORTED");
        }
        if ("hookOnline".equals(method) && !self) {
            int api = extras == null ? 0 : extras.getInt("api", 0);
            long version = extras == null ? 0 : extras.getLong("versionCode", 0);
            getContext().getSharedPreferences("ownership-hook", 0).edit()
                    .putLong("lastSeenMs", System.currentTimeMillis())
                    .putInt("api", api)
                    .putLong("versionCode", version)
                    .apply();
        }
        LocalPrefs state = LocalPrefs.open(getContext(), "ownership");
        Bundle result = new Bundle();
        result.putString("mode", state.getString("mode", "OFFICIAL"));
        result.putBoolean("native", "NATIVE".equals(state.getString("mode", "OFFICIAL"))
                && state.getBoolean("hookExclusive", false));
        result.putLong("generation", state.getLong("generation", 0));
        result.putString("mac", LocalPrefs.open(getContext(), "band-state").getString("mac", ""));
        var hook = getContext().getSharedPreferences("ownership-hook", 0);
        result.putInt("hookApi", hook.getInt("api", 0));
        result.putLong("hookVersionCode", hook.getLong("versionCode", 0));
        result.putLong("hookLastSeenMs", hook.getLong("lastSeenMs", 0));
        return result;
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection, String[] args, String sort) {
        throw new SecurityException("OWNERSHIP_CALL_ONLY");
    }
    @Override public String getType(Uri uri) { return null; }
    @Override public Uri insert(Uri uri, ContentValues values) { throw new SecurityException("OWNERSHIP_CALL_ONLY"); }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] args) {
        throw new SecurityException("OWNERSHIP_CALL_ONLY");
    }
    @Override public int delete(Uri uri, String selection, String[] args) {
        throw new SecurityException("OWNERSHIP_CALL_ONLY");
    }
}
