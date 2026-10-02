// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.service;

import android.app.NotificationManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.database.ContentObserver;
import android.os.SystemClock;
import io.github.miam1ku.mibandoplusbridge.notify.PhoneDnd;
import io.github.miam1ku.mibandoplusbridge.protocol.BandDndCommand;
import io.github.miam1ku.mibandoplusbridge.protocol.BandWeatherEncoder;
import io.github.miam1ku.mibandoplusbridge.protocol.CommandTransport;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import nodomain.freeyourgadget.gadgetbridge.proto.xiaomi.XiaomiProto;

/**
 * Event-driven control plane for COEXIST mode.
 *
 * It owns no Bluetooth transport. Commands use Mi Fitness' authenticated WearApiCall and the
 * worker is allowed to time out while idle.
 */
public final class CoexistControlPlane {
    private static final long WEATHER_RETRY_NANOS = TimeUnit.MINUTES.toNanos(30);
    private static CoexistControlPlane instance;

    private final Context context;
    private final ScheduledThreadPoolExecutor worker;
    private final CommandTransport transport;
    private final WeatherSync weather;
    private final ContentObserver dndObserver;
    private final BroadcastReceiver dndReceiver;
    private boolean dndRegistered;
    private long lastWeatherAttemptNanos;
    private int lastDndFilter = Integer.MIN_VALUE;
    private long lastDndSyncNanos;

    private CoexistControlPlane(Context context) {
        Context app = context.getApplicationContext();
        this.context = app == null ? context : app;
        worker = new ScheduledThreadPoolExecutor(1, runnable -> {
            Thread thread = new Thread(runnable, "OplusCoexistControl");
            thread.setDaemon(true);
            thread.setPriority(Thread.MIN_PRIORITY);
            return thread;
        });
        worker.setRemoveOnCancelPolicy(true);
        worker.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        worker.setKeepAliveTime(15, TimeUnit.SECONDS);
        worker.allowCoreThreadTimeOut(true);
        transport = CoexistProtoRelay.transport(this.context);
        weather = new WeatherSync(this.context, () -> transport, worker);
        dndObserver = new ContentObserver(null) {
            @Override public void onChange(boolean selfChange) { scheduleDnd(false); }
        };
        dndReceiver = new BroadcastReceiver() {
            @Override public void onReceive(Context ignored, Intent intent) {
                if (NotificationManager.ACTION_INTERRUPTION_FILTER_CHANGED.equals(intent.getAction())) {
                    scheduleDnd(false);
                }
            }
        };
        registerDndSignals();
    }

    private static synchronized CoexistControlPlane get(Context context) {
        if (instance == null || instance.worker.isShutdown()) {
            instance = new CoexistControlPlane(context);
        }
        return instance;
    }

    public static void relayOnline(Context context) {
        if (context == null || !new OwnershipController(context).coexistReady()) return;
        get(context).onRelayOnline();
    }

    public static void onCommand(Context context, XiaomiProto.Command command) {
        if (context == null || command == null || command.getType() != 10
                || !new OwnershipController(context).coexistReady()) return;
        get(context).weather.onCommand(command);
    }

    public static CompletionStage<Void> requestWeather(Context context,
            BandWeatherEncoder.Sample sample, boolean inspect) {
        CoexistControlPlane control = get(context);
        return inspect ? control.weather.inspectCities(sample) : control.weather.send(sample);
    }

    public static void refreshWeather(Context context) {
        if (context == null || !new OwnershipController(context).coexistReady()) return;
        get(context).weather.refreshAndSend();
    }

    private void onRelayOnline() {
        scheduleDnd(true);
        long now = SystemClock.elapsedRealtimeNanos();
        synchronized (this) {
            if (lastWeatherAttemptNanos != 0 && now - lastWeatherAttemptNanos < WEATHER_RETRY_NANOS) {
                return;
            }
            lastWeatherAttemptNanos = now;
        }
        weather.sendIfChanged();
    }

    private void registerDndSignals() {
        if (dndRegistered) return;
        try {
            var resolver = context.getContentResolver();
            resolver.registerContentObserver(
                    android.provider.Settings.Global.getUriFor("zen_mode"), false, dndObserver);
            resolver.registerContentObserver(
                    android.provider.Settings.Secure.getUriFor("focusmode_switch"), false, dndObserver);
            resolver.registerContentObserver(
                    android.provider.Settings.Secure.getUriFor("focusmode_switch_new"), false, dndObserver);
            resolver.registerContentObserver(
                    android.provider.Settings.Secure.getUriFor("op_breath_mode_status"), false, dndObserver);
            context.registerReceiver(dndReceiver,
                    new IntentFilter(NotificationManager.ACTION_INTERRUPTION_FILTER_CHANGED),
                    Context.RECEIVER_NOT_EXPORTED);
            dndRegistered = true;
        } catch (RuntimeException unavailable) {
            io.github.miam1ku.mibandoplusbridge.data.SessionLog.line(
                    context, "COEXIST_DND_OBSERVER unavailable");
        }
    }

    private void scheduleDnd(boolean forced) {
        if (!new OwnershipController(context).coexistReady()) return;
        try {
            worker.execute(() -> syncDnd(forced));
        } catch (java.util.concurrent.RejectedExecutionException ignored) { }
    }

    private void syncDnd(boolean forced) {
        if (!new OwnershipController(context).coexistReady()) return;
        int filter = PhoneDnd.currentFilter(context);
        long now = System.nanoTime();
        synchronized (this) {
            long elapsed = lastDndSyncNanos == 0 ? -1 : now - lastDndSyncNanos;
            if (!forced && PhoneDnd.repeatSync(lastDndFilter, elapsed, filter)) return;
            if (!forced && filter == lastDndFilter) return;
            lastDndFilter = filter;
            lastDndSyncNanos = now;
        }
        boolean on = PhoneDnd.blocksNotifications(filter);
        io.github.miam1ku.mibandoplusbridge.data.SessionLog.line(
                context, "COEXIST_DND_SYNC " + PhoneDnd.describe(context));

        transport.send(BandDndCommand.syncWithPhone()).whenComplete((ignored, firstError) -> {
            if (firstError != null) return;
            try {
                worker.execute(() -> sendDndFollowup(on));
            } catch (java.util.concurrent.RejectedExecutionException ignored2) { }
        });
    }

    private void sendDndFollowup(boolean on) {
        if (!new OwnershipController(context).coexistReady()) return;
        int activatedAt = (int) System.currentTimeMillis();
        transport.send(BandDndCommand.state(on));
        transport.send(BandDndCommand.phoneSilent(on));
        transport.send(BandDndCommand.queryRules());
        transport.send(BandDndCommand.phoneRules(on, activatedAt));
        try {
            worker.schedule(() -> {
                if (!new OwnershipController(context).coexistReady()) return;
                boolean latest = PhoneDnd.blocksNotifications(PhoneDnd.currentFilter(context));
                transport.send(BandDndCommand.phoneSilent(latest));
                transport.send(BandDndCommand.phoneRules(latest, (int) System.currentTimeMillis()));
            }, 2, TimeUnit.SECONDS);
        } catch (java.util.concurrent.RejectedExecutionException ignored) { }
    }
}
