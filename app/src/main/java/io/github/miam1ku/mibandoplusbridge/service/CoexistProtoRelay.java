// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.service;

import android.content.Context;
import android.os.Bundle;
import io.github.miam1ku.mibandoplusbridge.integration.CoexistRelayProvider;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import nodomain.freeyourgadget.gadgetbridge.proto.xiaomi.XiaomiProto;

/** Chooses the Mi Fitness official TYPE_PROTO session first, native short lease only as fallback. */
public final class CoexistProtoRelay {
    private static final int ONE_WAY_TIMEOUT_MS = 5_000;
    private static final int SAFE_PAYLOAD = 16 * 1024;

    private CoexistProtoRelay() {}

    public static boolean ready(Context context) {
        if (context == null) return false;
        OwnershipController owner = new OwnershipController(context);
        if (owner.coexistReady()) {
            try {
                Bundle status = context.getContentResolver().call(
                        CoexistRelayProvider.URI, "status", null, null);
                return status != null && status.getBoolean("online", false);
            } catch (RuntimeException unavailable) {
                return false;
            }
        }
        return owner.nativeReady() && BandLiveService.notificationSessionReady(context);
    }

    public static int payloadLimit(Context context) {
        OwnershipController owner = new OwnershipController(context);
        if (owner.coexistReady()) return SAFE_PAYLOAD;
        return BandLiveService.notificationPayloadLimit();
    }

    public static CompletionStage<Void> send(Context context, XiaomiProto.Command command) {
        if (context == null || command == null || !command.isInitialized()) {
            return failed("RELAY_COMMAND_INVALID");
        }
        OwnershipController owner = new OwnershipController(context);
        if (!owner.coexistReady()) {
            if (owner.nativeReady()) return BandLiveService.sendSessionCommand(command);
            return failed("COEXIST_NOT_READY");
        }
        byte[] payload = command.toByteArray();
        if (payload.length == 0 || payload.length > CoexistRelayProvider.MAX_PAYLOAD) {
            return failed("RELAY_PAYLOAD_TOO_LARGE");
        }
        if (command.getType() == 2 && (command.getSubtype() == 15
                || command.getSubtype() == 23 || command.getSubtype() == 44
                || command.getSubtype() == 109 || command.getSubtype() == 110)) {
            CoexistEventRouter.noteDndSent();
        }
        Bundle request = new Bundle();
        request.putByteArray("payload", payload);
        request.putBoolean("needResponse", false);
        request.putInt("timeoutMs", ONE_WAY_TIMEOUT_MS);
        try {
            Bundle result = context.getContentResolver().call(
                    CoexistRelayProvider.URI, "submit", null, request);
            String status = result == null ? "RELAY_UNAVAILABLE" : result.getString("status", "");
            return "QUEUED".equals(status) ? CompletableFuture.completedFuture(null) : failed(status);
        } catch (RuntimeException unavailable) {
            return failed("RELAY_UNAVAILABLE");
        } finally {
            java.util.Arrays.fill(payload, (byte) 0);
            request.clear();
        }
    }

    private static CompletionStage<Void> failed(String reason) {
        return CompletableFuture.failedFuture(new IllegalStateException(
                reason == null || reason.isBlank() ? "RELAY_FAILED" : reason));
    }
}
