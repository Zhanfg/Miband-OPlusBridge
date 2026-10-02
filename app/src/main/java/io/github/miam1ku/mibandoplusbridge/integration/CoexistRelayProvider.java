// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.integration;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.Process;
import android.os.SystemClock;
import io.github.miam1ku.mibandoplusbridge.HostIdentity;
import io.github.miam1ku.mibandoplusbridge.data.LocalPrefs;
import io.github.miam1ku.mibandoplusbridge.service.CoexistControlPlane;
import io.github.miam1ku.mibandoplusbridge.service.CoexistEventRouter;
import io.github.miam1ku.mibandoplusbridge.service.CoexistProtoRelay;
import io.github.miam1ku.mibandoplusbridge.protocol.BandNotificationCommand;
import java.util.ArrayDeque;
import java.util.Iterator;
import nodomain.freeyourgadget.gadgetbridge.proto.xiaomi.XiaomiProto;

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

    @Override public boolean onCreate() { return true; }

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
            case "offline" -> {
                if (!mi) throw new SecurityException("MI_FITNESS_CALLER_REQUIRED");
                yield offline(extras);
            }
            case "complete" -> {
                if (!mi) throw new SecurityException("MI_FITNESS_CALLER_REQUIRED");
                yield complete(extras);
            }
            case "event" -> {
                if (!mi) throw new SecurityException("MI_FITNESS_CALLER_REQUIRED");
                yield event(extras);
            }
            case "cancelCall" -> {
                if (!self) throw new SecurityException("RELAY_OWNER_ONLY");
                yield cancelCall();
            }
            case "cancelRequest" -> {
                if (!self) throw new SecurityException("RELAY_OWNER_ONLY");
                yield cancelRequest(extras);
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
        getContext().getContentResolver().notifyChange(DeviceCardProvider.URI, null);
        if (out.getBoolean("online", false)) {
            long token = Binder.clearCallingIdentity();
            try {
                CoexistControlPlane.relayOnline(getContext());
            } finally {
                Binder.restoreCallingIdentity(token);
            }
        }
        return out;
    }

    private Bundle offline(Bundle extras) {
        String address = extras == null ? "" : extras.getString("address", "");
        if (!address.isBlank() && selectedAddress().equalsIgnoreCase(address)) {
            onlineAt = 0;
            onlineAddress = "";
            getContext().getContentResolver().notifyChange(URI, null);
            getContext().getContentResolver().notifyChange(DeviceCardProvider.URI, null);
        }
        return relayStatus();
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

    private Bundle cancelRequest(Bundle extras) {
        long id = extras == null ? -1 : extras.getLong("requestId", -1);
        if (id <= 0) return status("RELAY_REQUEST_INVALID");
        for (Iterator<Request> it = pending.iterator(); it.hasNext();) {
            Request request = it.next();
            if (request.id != id) continue;
            it.remove();
            java.util.Arrays.fill(request.payload, (byte) 0);
            Bundle out = status("RELAY_REQUEST_CANCELLED");
            out.putLong("requestId", id);
            return out;
        }
        Bundle out = status("RELAY_REQUEST_NOT_PENDING");
        out.putLong("requestId", id);
        return out;
    }

    private Bundle cancelCall() {
        int removed = 0;
        for (Iterator<Request> it = pending.iterator(); it.hasNext();) {
            Request request = it.next();
            if (!callPayload(request.payload)) continue;
            it.remove();
            java.util.Arrays.fill(request.payload, (byte) 0);
            CoexistProtoRelay.completeFromProvider(
                    request.id, "CALL_CANCELLED", -1, null);
            removed++;
        }
        Bundle out = status("CALL_QUEUE_CANCELLED");
        out.putInt("removed", removed);
        return out;
    }

    private static boolean callPayload(byte[] payload) {
        try {
            XiaomiProto.Command command = XiaomiProto.Command.parseFrom(payload);
            if (command.getType() != 7 || !command.hasNotification()) return false;
            if (command.getSubtype() == 0
                    && command.getNotification().hasNotification2()
                    && command.getNotification().getNotification2().hasNotification3()) {
                return BandNotificationCommand.isCall(
                        command.getNotification().getNotification2().getNotification3());
            }
            if (command.getSubtype() == 1
                    && command.getNotification().hasNotificationDismiss()) {
                var dismiss = command.getNotification().getNotificationDismiss();
                if (dismiss.getNotificationIdCount() != 1) return false;
                var id = dismiss.getNotificationId(0);
                return "phone".equals(id.getPackage()) && id.getId() == 0;
            }
        } catch (Exception ignored) { }
        return false;
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
