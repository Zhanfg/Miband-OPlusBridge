// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.integration;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.ContentObserver;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.os.SystemClock;
import io.github.miam1ku.mibandoplusbridge.HostIdentity;
import io.github.miam1ku.mibandoplusbridge.data.LocalPrefs;
import io.github.miam1ku.mibandoplusbridge.service.CoexistEventRouter;
import io.github.miam1ku.mibandoplusbridge.service.CoexistProtoRelay;
import io.github.miam1ku.mibandoplusbridge.notify.PhoneDnd;
import io.github.miam1ku.mibandoplusbridge.protocol.BandDndCommand;
import java.util.ArrayDeque;

/** Bounded command mailbox between the bridge process and Mi Fitness' authenticated WearApiCall. */
public final class CoexistRelayProvider extends ContentProvider {
    public static final Uri URI = Uri.parse("content://io.github.miam1ku.mibandoplusbridge.relay");
    public static final int MAX_PAYLOAD = 32 * 1024;
    private static final int CAPACITY = 64;
    private static final long TTL_MS = 20_000;
    private static final long ONLINE_TTL_MS = 10 * 60_000L;
    private final ArrayDeque<Request> pending = new ArrayDeque<>();
    private long onlineAt;
    private String onlineAddress = "";
    private int lastDndFilter = Integer.MIN_VALUE;
    private long lastDndAtNanos;
    private ContentObserver dndObserver;

    @Override public boolean onCreate() {
        Handler handler = new Handler(Looper.getMainLooper());
        dndObserver = new ContentObserver(handler) {
            @Override public void onChange(boolean selfChange) { syncDnd(); }
        };
        try {
            var resolver = getContext().getContentResolver();
            resolver.registerContentObserver(
                    android.provider.Settings.Global.getUriFor("zen_mode"), false, dndObserver);
            resolver.registerContentObserver(
                    android.provider.Settings.Secure.getUriFor("focusmode_switch"), false, dndObserver);
            resolver.registerContentObserver(
                    android.provider.Settings.Secure.getUriFor("focusmode_switch_new"), false, dndObserver);
            resolver.registerContentObserver(
                    android.provider.Settings.Secure.getUriFor("op_breath_mode_status"), false, dndObserver);
        } catch (RuntimeException ignored) { }
        return true;
    }

    @Override public synchronized Bundle call(String method, String arg, Bundle extras) {
        if (method == null) throw new SecurityException("RELAY_METHOD_REQUIRED");
        boolean self = Binder.getCallingUid() == Process.myUid();
        boolean mi = !self && HostIdentity.uidHas(getContext(), Binder.getCallingUid(), HostIdentity.MI_PACKAGE);
        return switch (method) {
            case "submit" -> {
                if (!self) throw new SecurityException("RELAY_OWNER_ONLY");
                yield submit(extras);
            }
            case "poll" -> {
                if (!mi) throw new SecurityException("MI_FITNESS_CALLER_REQUIRED");
                yield poll(extras);
            }
            case "online" -> {
                if (!mi) throw new SecurityException("MI_FITNESS_CALLER_REQUIRED");
                yield online(extras);
            }
            case "complete" -> {
                if (!mi) throw new SecurityException("MI_FITNESS_CALLER_REQUIRED");
                yield complete(extras);
            }
            case "event" -> {
                if (!mi) throw new SecurityException("MI_FITNESS_CALLER_REQUIRED");
                yield event(extras);
            }
            case "status" -> {
                if (!self) throw new SecurityException("RELAY_OWNER_ONLY");
                yield relayStatus();
            }
            default -> throw new SecurityException("RELAY_METHOD_UNSUPPORTED");
        };
    }

    private Bundle submit(Bundle extras) {
        if (!coexist()) return status("COEXIST_NOT_READY");
        byte[] payload = extras == null ? null : extras.getByteArray("payload");
        int timeout = extras == null ? 5_000 : extras.getInt("timeoutMs", 5_000);
        boolean response = extras != null && extras.getBoolean("needResponse", false);
        if (payload == null || payload.length == 0 || payload.length > MAX_PAYLOAD
                || timeout < 500 || timeout > 30_000) {
            return status("RELAY_REQUEST_INVALID");
        }
        expire();
        if (pending.size() >= CAPACITY) return status("RELAY_QUEUE_FULL");
        long id = extras.getLong("requestId", -1);
        if (id <= 0) return status("RELAY_REQUEST_INVALID");
        for (Request existing : pending) if (existing.id == id) return status("RELAY_REQUEST_DUPLICATE");
        pending.addLast(new Request(id, payload.clone(), response, timeout, SystemClock.elapsedRealtime()));
        getContext().getContentResolver().notifyChange(URI, null);
        Bundle out = status("QUEUED");
        out.putLong("requestId", id);
        return out;
    }

    private Bundle poll(Bundle extras) {
        String address = extras == null ? "" : extras.getString("address", "");
        if (address.isBlank() || !selectedAddress().equalsIgnoreCase(address) || !coexist()) {
            return status("NO_REQUEST");
        }
        onlineAt = SystemClock.elapsedRealtime();
        onlineAddress = address;
        expire();
        Request request = pending.pollFirst();
        if (request == null) return status("NO_REQUEST");
        Bundle out = status("REQUEST");
        out.putLong("requestId", request.id);
        byte[] payload = request.payload.clone();
        out.putByteArray("payload", payload);
        java.util.Arrays.fill(request.payload, (byte) 0);
        out.putBoolean("needResponse", request.needResponse);
        out.putInt("timeoutMs", request.timeoutMs);
        return out;
    }

    private Bundle online(Bundle extras) {
        String address = extras == null ? "" : extras.getString("address", "");
        if (!address.isBlank() && selectedAddress().equalsIgnoreCase(address) && coexist()) {
            onlineAt = SystemClock.elapsedRealtime();
            onlineAddress = address;
        }
        Bundle out = relayStatus();
        getContext().getContentResolver().notifyChange(URI, null);
        if (out.getBoolean("online", false)) syncDnd();
        return out;
    }

    private void syncDnd() {
        if (!coexist() || !onlineNow()) return;
        int filter = PhoneDnd.currentFilter(getContext());
        long now = System.nanoTime();
        synchronized (this) {
            long elapsed = lastDndAtNanos == 0 ? -1 : now - lastDndAtNanos;
            if (PhoneDnd.repeatSync(lastDndFilter, elapsed, filter)) return;
            lastDndFilter = filter;
            lastDndAtNanos = now;
        }
        for (var command : BandDndCommand.mirror(filter)) {
            CoexistProtoRelay.send(getContext(), command);
        }
    }

    private Bundle complete(Bundle extras) {
        if (extras == null) return status("RELAY_RESULT_INVALID");
        long id = extras.getLong("requestId", -1);
        String resultStatus = extras.getString("status", "FAILED");
        int resultCode = extras.getInt("resultCode", -1);
        byte[] payload = extras.getByteArray("payload");
        if (id <= 0 || payload != null && payload.length > MAX_PAYLOAD) {
            return status("RELAY_RESULT_INVALID");
        }
        CoexistProtoRelay.completeFromProvider(id, resultStatus, resultCode,
                payload == null ? null : payload.clone());
        return status("RELAY_RESULT_RECORDED");
    }

    private Bundle event(Bundle extras) {
        String address = extras == null ? "" : extras.getString("address", "");
        byte[] payload = extras == null ? null : extras.getByteArray("payload");
        if (payload == null || payload.length == 0 || payload.length > MAX_PAYLOAD
                || !selectedAddress().equalsIgnoreCase(address) || !coexist()) {
            return status("EVENT_REJECTED");
        }
        long token = Binder.clearCallingIdentity();
        try {
            CoexistEventRouter.accept(getContext(), payload);
        } finally {
            Binder.restoreCallingIdentity(token);
        }
        return status("EVENT_ACCEPTED");
    }

    private Bundle relayStatus() {
        Bundle out = status(onlineNow() ? "RELAY_ONLINE" : "RELAY_OFFLINE");
        out.putBoolean("online", onlineNow());
        out.putInt("queued", pending.size());
        out.putString("address", onlineAddress);
        return out;
    }

    private void expire() {
        long now = SystemClock.elapsedRealtime();
        while (!pending.isEmpty() && now - pending.peekFirst().createdAt > TTL_MS) {
            Request expired = pending.removeFirst();
            java.util.Arrays.fill(expired.payload, (byte) 0);
        }
    }

    private boolean onlineNow() {
        long now = SystemClock.elapsedRealtime();
        return onlineAt > 0 && now >= onlineAt && now - onlineAt < ONLINE_TTL_MS;
    }

    private boolean coexist() {
        LocalPrefs state = LocalPrefs.open(getContext(), "ownership");
        return "COEXIST".equals(state.getString("mode", "OFFICIAL"))
                && !state.getBoolean("hookExclusive", false);
    }

    private String selectedAddress() {
        return LocalPrefs.open(getContext(), "band-state").getString("mac", "");
    }

    private static Bundle status(String value) {
        Bundle out = new Bundle();
        out.putString("status", value);
        return out;
    }

    private record Request(long id, byte[] payload, boolean needResponse, int timeoutMs, long createdAt) {}

    @Override public Cursor query(Uri uri, String[] projection, String selection, String[] args, String sort) {
        throw new SecurityException("RELAY_CALL_ONLY");
    }
    @Override public String getType(Uri uri) { return null; }
    @Override public Uri insert(Uri uri, ContentValues values) { throw new SecurityException("RELAY_CALL_ONLY"); }
    @Override public int delete(Uri uri, String selection, String[] args) { throw new SecurityException("RELAY_CALL_ONLY"); }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] args) {
        throw new SecurityException("RELAY_CALL_ONLY");
    }
}
