// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.hook;

import android.content.Context;
import android.os.Bundle;
import android.util.Log;
import io.github.miam1ku.mibandoplusbridge.integration.HealthQueueProvider;
import java.lang.reflect.Method;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Mirrors already-parsed Mi Fitness local health records into the bridge.
 * No Bluetooth transport, authentication material or raw protocol payload is touched here.
 */
public final class MiHealthMirrorHook {
    private static final String TAG = "OplusBandBridge";
    private static final int BATCH = 64;
    private static final long BACKFILL_WINDOW_SECONDS = 48L * 60L * 60L;
    private static volatile ThreadPoolExecutor writer;
    private static volatile Backfill backfill;
    private static volatile long lastBackfillGeneration = -1;

    private MiHealthMirrorHook() {}

    public static synchronized void install(Context context, ClassLoader loader) throws Exception {
        if (writer != null && !writer.isShutdown()) return;
        ThreadPoolExecutor executor = new ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(8), runnable -> {
                    Thread thread = new Thread(runnable, "OplusBandHealthMirror");
                    thread.setDaemon(true);
                    thread.setPriority(Thread.MIN_PRIORITY);
                    return thread;
                });
        writer = executor;

        Class<?> utils = HookResolver.resolveClassByMembers(context, loader,
                "com.xiaomi.fit.fitness.persist.db.utils.DailyRecordDaoUtils",
                "com.xiaomi.fit.fitness.persist.db.", null,
                new String[]{"recordDailyRecordToDB", "recordServerDailyDataToDB"}, new String[0]);
        Method local = HookResolver.resolveMethod(utils, "recordDailyRecordToDB", boolean.class,
                String.class, String.class, List.class, boolean.class);
        XposedBridge.hookMethod(local, new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam param) {
                if (param.hasThrowable() || !Boolean.TRUE.equals(param.getResult())) return;
                if (!(param.args[2] instanceof List<?> models) || models.isEmpty()) return;
                mirror(context, param.args[0] instanceof String key ? key : "",
                        param.args[1] instanceof String sid ? sid : "", models);
            }
        });
        Log.i(TAG, "MI_HEALTH_MIRROR_READY " + utils.getName());
    }

    public static synchronized void detach() {
        ThreadPoolExecutor current = writer;
        writer = null;
        if (current != null) current.shutdownNow();
    }

    private static void mirror(Context context, String persistKey, String sid, List<?> models) {
        ArrayList<Row> rows = new ArrayList<>(Math.min(models.size() * 2, 512));
        for (Object model : models) {
            if (model == null) continue;
            try {
                Object item = XposedHelpers.callMethod(model, "getItem");
                if (item == null) continue;
                String simple = item.getClass().getSimpleName();
                if ("DayNightSleepReport".equals(simple) || "SleepSegmentReport".equals(simple)) {
                    appendSleepRows(persistKey, sid, model, item, rows);
                    continue;
                }
                Row row = row(persistKey, sid, model, item);
                if (row != null) rows.add(row);
            } catch (Throwable ignored) { }
        }
        if (rows.isEmpty()) return;

        ThreadPoolExecutor queue = writer;
        if (queue == null || queue.isShutdown()) return;
        try {
            queue.execute(() -> pushRows(context, rows));
        } catch (RuntimeException full) {
            Log.i(TAG, "MI_HEALTH_MIRROR_QUEUE_FULL");
        }
    }

    private static Row row(String persistKey, String sid, Object model, Object item) {
        if (item == null) return null;
        String simple = item.getClass().getSimpleName();
        String kind;
        String getter;
        if ("StepItem".equals(simple)) {
            kind = "steps_interval";
            getter = "getSteps";
        } else if ("HrItem".equals(simple)) {
            kind = "heart_rate";
            getter = "getHr";
        } else if ("Spo2Item".equals(simple)) {
            kind = "spo2";
            getter = "getSpo2";
        } else if ("StressItem".equals(simple)) {
            kind = "stress";
            getter = "getStress";
        } else {
            return null;
        }

        Object rawValue = XposedHelpers.callMethod(item, getter);
        if (!(rawValue instanceof Number number)) return null;
        int value = number.intValue();
        if (value < 0 || !"steps_interval".equals(kind) && value <= 0) return null;

        long timestamp = number(item, "getTimestamp");
        if (timestamp <= 0) timestamp = number(model, "getTime");
        long startMs = toMillis(timestamp);
        if (startMs <= 0 || startMs > Long.MAX_VALUE - 60_000L) return null;

        int distance = -1;
        int calories = -1;
        if ("steps_interval".equals(kind)) {
            Object rawDistance = safeCall(item, "getDistance");
            if (rawDistance instanceof Number measured && measured.intValue() >= 0) {
                distance = measured.intValue();
            }
            Object rawCalories = safeCall(item, "getCalories");
            if (rawCalories instanceof Number measured && Float.isFinite(measured.floatValue())
                    && measured.floatValue() >= 0f) {
                calories = Math.round(measured.floatValue());
            }
        }
        Object zone = safeCall(model, "getZoneName");
        String timezone = zone instanceof String text ? text : "";
        String sourceKey = persistKey + "|" + sid + "|" + timestamp + "|" + item.getClass().getName();
        return new Row(sourceKey, kind, startMs, startMs + 60_000L,
                value, distance, calories, -1, false, timezone);
    }

    private static void appendSleepRows(String persistKey, String sid, Object model, Object item,
            List<Row> rows) {
        long bed = toMillis(number(item, "getBedTime"));
        long wake = toMillis(number(item, "getWakeUpTime"));
        if (wake <= 0) wake = toMillis(number(item, "getWakeupTime"));
        if (bed <= 0 || wake <= bed) return;

        Object zone = safeCall(model, "getZoneName");
        String timezone = zone instanceof String text ? text : "";
        boolean complete = false;
        Object modelComplete = safeCall(model, "isCompleteSleep");
        if (modelComplete instanceof Boolean value) {
            complete = value;
        } else {
            Object incomplete = safeCall(item, "isUncomplete");
            if (incomplete instanceof Boolean value) complete = !value;
            else {
                Object valid = safeCall(item, "isValidSleep");
                complete = valid instanceof Boolean value && value;
            }
        }

        String base = persistKey + "|" + sid + "|" + item.getClass().getName() + "|" + bed;
        rows.add(new Row(base + "|session", "sleep_interval", bed, wake,
                0, -1, -1, -1, complete, timezone));

        Object rawStages = safeCall(item, "getSleepItems");
        if (!(rawStages instanceof List<?> stages)) return;
        for (Object stageItem : stages) {
            if (stageItem == null) continue;
            long start = toMillis(number(stageItem, "getStartTime"));
            long end = toMillis(number(stageItem, "getEndTime"));
            int stage = (int) number(stageItem, "getSleepState");
            if (stage < 2 || stage > 5) continue;
            start = Math.max(start, bed);
            end = Math.min(end, wake);
            if (start <= 0 || end <= start) continue;
            rows.add(new Row(base + "|stage|" + start, "sleep_stage", start, end,
                    0, -1, -1, stage, false, timezone));
        }
    }

    private static Bundle bundle(List<Row> rows) {
        int size = rows.size();
        String[] sourceKeys = new String[size];
        String[] kinds = new String[size];
        long[] starts = new long[size];
        long[] ends = new long[size];
        int[] values = new int[size];
        int[] distances = new int[size];
        int[] calories = new int[size];
        int[] stages = new int[size];
        boolean[] completes = new boolean[size];
        String[] timezones = new String[size];
        for (int i = 0; i < size; i++) {
            Row row = rows.get(i);
            sourceKeys[i] = row.sourceKey;
            kinds[i] = row.kind;
            starts[i] = row.startMs;
            ends[i] = row.endMs;
            values[i] = row.value;
            distances[i] = row.distance;
            calories[i] = row.calories;
            stages[i] = row.stage;
            completes[i] = row.complete;
            timezones[i] = row.timezone;
        }
        Bundle payload = new Bundle();
        payload.putStringArray("sourceKeys", sourceKeys);
        payload.putStringArray("kinds", kinds);
        payload.putLongArray("starts", starts);
        payload.putLongArray("ends", ends);
        payload.putIntArray("values", values);
        payload.putIntArray("distances", distances);
        payload.putIntArray("calories", calories);
        payload.putIntArray("stages", stages);
        payload.putBooleanArray("completes", completes);
        payload.putStringArray("timezones", timezones);
        return payload;
    }

    private static void pushRows(Context context, List<Row> rows) {
        for (int offset = 0; offset < rows.size(); offset += BATCH) {
            int end = Math.min(rows.size(), offset + BATCH);
            Bundle payload = bundle(rows.subList(offset, end));
            try {
                Bundle result = context.getContentResolver().call(
                        HealthQueueProvider.URI, "mirrorBatch", null, payload);
                if (result != null && result.getInt("added", 0) > 0) {
                    Log.i(TAG, "MI_HEALTH_MIRROR "
                            + result.getString("status", "unknown")
                            + " added=" + result.getInt("added", 0));
                }
            } catch (RuntimeException rejected) {
                Log.i(TAG, "MI_HEALTH_MIRROR_REJECTED " + rejected.getClass().getSimpleName());
                return;
            } finally {
                payload.clear();
            }
        }
    }

    private static long number(Object target, String getter) {
        Object value = safeCall(target, getter);
        return value instanceof Number number ? number.longValue() : 0L;
    }

    private static Object safeCall(Object target, String getter) {
        if (target == null) return null;
        try { return XposedHelpers.callMethod(target, getter); }
        catch (Throwable ignored) { return null; }
    }

    private static long toMillis(long time) {
        return time > 0 && time < 10_000_000_000L ? time * 1000L : time;
    }

    private record Row(String sourceKey, String kind, long startMs, long endMs,
                       int value, int distance, int calories, int stage,
                       boolean complete, String timezone) {}
}
