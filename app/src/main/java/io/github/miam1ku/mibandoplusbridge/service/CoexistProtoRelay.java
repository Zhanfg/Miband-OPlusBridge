// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.service;

import android.content.Context;
import android.os.Bundle;
import io.github.miam1ku.mibandoplusbridge.integration.CoexistRelayProvider;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import nodomain.freeyourgadget.gadgetbridge.proto.xiaomi.XiaomiProto;

/** Chooses the Mi Fitness official TYPE_PROTO session first, native short lease only as fallback. */
public final class CoexistProtoRelay {
    private static final int ONE_WAY_TIMEOUT_MS = 5_000;
    private static final int RESPONSE_TIMEOUT_MS = 10_000;
    private static final int SAFE_PAYLOAD = 16 * 1024;
    private static final AtomicLong IDS = new AtomicLong(1);
    private static final ConcurrentHashMap<Long, Pending> PENDING = new ConcurrentHashMap<>();
    private static final ScheduledThreadPoolExecutor TIMEOUTS = timeoutWorker();

    private CoexistProtoRelay() {}

    private static ScheduledThreadPoolExecutor timeoutWorker() {
        ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(1, runnable -> {
            Thread thread = new Thread(runnable, "OplusRelayTimeout");
            thread.setDaemon(true);
            thread.setPriority(Thread.MIN_PRIORITY);
            return thread;
        });
        executor.setRemoveOnCancelPolicy(true);
        executor.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        return executor;
    }

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
            return failedVoid("RELAY_COMMAND_INVALID");
        }
        OwnershipController owner = new OwnershipController(context);
        if (!owner.coexistReady()) {
            if (owner.nativeReady()) return BandLiveService.sendSessionCommand(command);
            return failedVoid("COEXIST_NOT_READY");
        }
        noteDnd(command);
        long id = nextId();
        return submit(context, id, command.toByteArray(), false, ONE_WAY_TIMEOUT_MS)
                .thenApply(ignored -> null);
    }

    public static CompletionStage<XiaomiProto.Command> request(Context context,
            XiaomiProto.Command command, int responseType, int responseSubtype) {
        if (context == null || command == null || !command.isInitialized()
                || responseType < 0 || responseSubtype < 0) {
            return failedCommand("RELAY_REQUEST_INVALID");
        }
        OwnershipController owner = new OwnershipController(context);
        if (!owner.coexistReady()) return failedCommand("COEXIST_NOT_READY");
        noteDnd(command);

        long id = nextId();
        CompletableFuture<XiaomiProto.Command> future = new CompletableFuture<>();
        Pending pending = new Pending(responseType, responseSubtype, future);
        PENDING.put(id, pending);
        TIMEOUTS.schedule(() -> {
            Pending expired = PENDING.remove(id);
            if (expired != null) {
                expired.future.completeExceptionally(
                        new java.util.concurrent.TimeoutException("RELAY_RESPONSE_TIMEOUT"));
            }
        }, RESPONSE_TIMEOUT_MS + 2_000L, TimeUnit.MILLISECONDS);

        submit(context, id, command.toByteArray(), true, RESPONSE_TIMEOUT_MS)
                .whenComplete((ignored, error) -> {
                    if (error == null) return;
                    Pending rejected = PENDING.remove(id);
                    if (rejected != null) rejected.future.completeExceptionally(error);
                });
        return future;
    }

    private static long nextId() {
        long id = IDS.getAndIncrement();
        if (id <= 0) {
            IDS.compareAndSet(id + 1, 1);
            id = IDS.getAndIncrement();
        }
        return id;
    }

    private static CompletionStage<Bundle> submit(Context context, long id, byte[] payload,
            boolean needResponse, int timeoutMs) {
        if (payload.length == 0 || payload.length > CoexistRelayProvider.MAX_PAYLOAD) {
            Arrays.fill(payload, (byte) 0);
            return CompletableFuture.failedFuture(new IllegalStateException("RELAY_PAYLOAD_TOO_LARGE"));
        }
        Bundle request = new Bundle();
        request.putLong("requestId", id);
        request.putByteArray("payload", payload);
        request.putBoolean("needResponse", needResponse);
        request.putInt("timeoutMs", timeoutMs);
        try {
            Bundle result = context.getContentResolver().call(
                    CoexistRelayProvider.URI, "submit", null, request);
            String status = result == null ? "RELAY_UNAVAILABLE" : result.getString("status", "");
            if (!"QUEUED".equals(status)) {
                return CompletableFuture.failedFuture(new IllegalStateException(
                        status == null || status.isBlank() ? "RELAY_FAILED" : status));
            }
            return CompletableFuture.completedFuture(result);
        } catch (RuntimeException unavailable) {
            return CompletableFuture.failedFuture(new IllegalStateException("RELAY_UNAVAILABLE"));
        } finally {
            Arrays.fill(payload, (byte) 0);
            request.clear();
        }
    }

    /** Called only by CoexistRelayProvider in the bridge process. */
    public static void completeFromProvider(long id, String status, int code, byte[] payload) {
        Pending pending = PENDING.remove(id);
        if (pending == null) {
            if (payload != null) Arrays.fill(payload, (byte) 0);
            return;
        }
        try {
            if ((!"OK".equals(status) && !"RESULT".equals(status)) || code != 0 || payload == null) {
                pending.future.completeExceptionally(new IllegalStateException(
                        status == null || status.isBlank() ? "RELAY_RESULT_FAILED" : status));
                return;
            }
            XiaomiProto.Command response = XiaomiProto.Command.parseFrom(payload);
            if (response.getType() != pending.responseType
                    || response.getSubtype() != pending.responseSubtype) {
                pending.future.completeExceptionally(
                        new IllegalStateException("RELAY_RESPONSE_MISMATCH"));
                return;
            }
            if (response.hasStatus() && response.getStatus() != 0) {
                pending.future.completeExceptionally(
                        new IllegalStateException("RELAY_COMMAND_REJECTED"));
                return;
            }
            pending.future.complete(response);
        } catch (Exception malformed) {
            pending.future.completeExceptionally(
                    new IllegalStateException("RELAY_RESPONSE_INVALID"));
        } finally {
            if (payload != null) Arrays.fill(payload, (byte) 0);
        }
    }

    private static void noteDnd(XiaomiProto.Command command) {
        if (command.getType() == 2 && (command.getSubtype() == 15
                || command.getSubtype() == 23 || command.getSubtype() == 44
                || command.getSubtype() == 109 || command.getSubtype() == 110)) {
            CoexistEventRouter.noteDndSent();
        }
    }

    private static CompletionStage<Void> failedVoid(String reason) {
        return CompletableFuture.failedFuture(new IllegalStateException(
                reason == null || reason.isBlank() ? "RELAY_FAILED" : reason));
    }

    private static CompletionStage<XiaomiProto.Command> failedCommand(String reason) {
        return CompletableFuture.failedFuture(new IllegalStateException(
                reason == null || reason.isBlank() ? "RELAY_FAILED" : reason));
    }

    private record Pending(int responseType, int responseSubtype,
                           CompletableFuture<XiaomiProto.Command> future) {}
}
