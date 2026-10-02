// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.service;

import android.content.Context;
import android.os.SystemClock;
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
    private long lastWeatherAttemptNanos;

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
        long now = SystemClock.elapsedRealtimeNanos();
        synchronized (this) {
            if (lastWeatherAttemptNanos != 0 && now - lastWeatherAttemptNanos < WEATHER_RETRY_NANOS) {
                return;
            }
            lastWeatherAttemptNanos = now;
        }
        weather.sendIfChanged();
    }
}
