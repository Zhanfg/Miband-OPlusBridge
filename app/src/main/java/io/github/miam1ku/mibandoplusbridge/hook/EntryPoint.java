// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.hook;

import android.app.Application;
import android.content.Context;
import android.util.Log;
import android.util.Pair;
import androidx.annotation.NonNull;
import io.github.libxposed.api.XposedModule;
import io.github.miam1ku.mibandoplusbridge.HostIdentity;
import io.github.miam1ku.mibandoplusbridge.OHealthHostProfile;
import java.lang.reflect.Executable;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Single modern libxposed API 102 entry.
 *
 * Hook IDs are stable per executable/ordinal, which lets API 102 atomically
 * replace them during hot reload and then detach handles that disappeared.
 */
public final class EntryPoint extends XposedModule {
    private static final String TAG = "OplusBandBridge";
    private static volatile EntryPoint current;
    private static final AtomicBoolean installed = new AtomicBoolean();
    private static final AtomicBoolean healthInstalled = new AtomicBoolean();

    private final ConcurrentHashMap<String, AtomicInteger> hookOrdinals = new ConcurrentHashMap<>();
    private final Set<String> hookedIds = ConcurrentHashMap.newKeySet();
    private Pair<String, ClassLoader> activePackage;

    @Override public void onModuleLoaded(@NonNull ModuleLoadedParam param) {
        current = this;
    }

    @Override public void onPackageReady(@NonNull PackageReadyParam param) {
        if (!param.isFirstPackage()) return;
        String packageName = param.getPackageName();
        ClassLoader loader = param.getClassLoader();
        activePackage = Pair.create(packageName, loader);
        beginInstall();
        installPackage(packageName, loader, false);
    }

    @Override public boolean onHotReloading(@NonNull HotReloadingParam param) {
        detachRuntimeResources();
        param.setSavedInstanceState(activePackage);
        return true;
    }

    private static void detachRuntimeResources() {
        try { MiFitnessOwnershipHook.detach(); } catch (Throwable ignored) {}
        try { MiFitnessImportHook.detach(); } catch (Throwable ignored) {}
        try { MyDevicesHook.detach(); } catch (Throwable ignored) {}
        try { OHealthWeatherHook.detach(); } catch (Throwable ignored) {}
        try { OHealthHealthImportHook.detach(); } catch (Throwable ignored) {}
        try { OHealthDeviceHook.detach(); } catch (Throwable ignored) {}
        try { OHealthSleepHook.detach(); } catch (Throwable ignored) {}
        try { OHealthFindPhoneHook.detach(); } catch (Throwable ignored) {}
        try { OHealthMusicHook.detach(); } catch (Throwable ignored) {}
    }

    @Override public void onHotReloaded(@NonNull HotReloadedParam param) {
        current = this;
        Object saved = param.getSavedInstanceState();
        if (saved instanceof Pair<?, ?> pair
                && pair.first instanceof String packageName
                && pair.second instanceof ClassLoader loader) {
            activePackage = Pair.create(packageName, loader);
            beginInstall();
            installPackage(packageName, loader, true);
        }
        param.getOldHookHandles().forEach(handle -> {
            String id = handle.getId();
            if (id == null || !hookedIds.contains(id)) handle.unhook();
        });
    }

    private void beginInstall() {
        hookOrdinals.clear();
        hookedIds.clear();
        // New module classloader has fresh static guards; make the intent explicit.
        installed.set(false);
        healthInstalled.set(false);
    }

    static void installHook(Executable executable, XC_MethodHook callback) {
        EntryPoint module = current;
        if (module == null) throw new IllegalStateException("LSP_MODULE_NOT_ATTACHED");
        executable.setAccessible(true);
        String base = executable.toGenericString();
        int ordinal = module.hookOrdinals.computeIfAbsent(base, ignored -> new AtomicInteger()).getAndIncrement();
        String id = base + "#" + ordinal;
        var builder = module.hook(executable);
        if (module.getApiVersion() >= 102) {
            builder.setId(id);
            module.hookedIds.add(id);
        }
        builder.intercept(chain -> XposedBridge.dispatch(executable, callback, chain));
    }

    static void logModern(int priority, String text, Throwable error) {
        EntryPoint module = current;
        if (module == null) return;
        try {
            module.log(priority, TAG, text == null ? "" : text, error);
        } catch (Throwable ignored) {
            // Android log is already emitted by callers.
        }
    }

    private void installPackage(String packageName, ClassLoader loader, boolean hotReload) {
        try {
            if ("com.coloros.alarmclock".equals(packageName)) {
                if (hotReload) {
                    Context context = currentApplication();
                    if (context != null) ClockAlarmHook.install(context, loader);
                } else {
                    hookAttach(loader, (context) -> ClockAlarmHook.install(context, loader));
                }
                return;
            }
            if (!HostIdentity.MI_PACKAGE.equals(packageName)
                    && !"com.heytap.mydevices".equals(packageName)
                    && !"com.heytap.health".equals(packageName)) return;

            if ("com.heytap.health".equals(packageName)) {
                Log.i(TAG, "OHEALTH_PACKAGE_LOADED process=" + Application.getProcessName());
                OHealthLoginDebug.install(loader);
                if (hotReload) {
                    Context context = currentApplication();
                    if (context != null) installHealth(context, loader);
                } else {
                    // Application.attach is earlier and stable across OHealth application-class renames.
                    hookAttach(loader, (context) -> installHealth(context, loader));
                }
                return;
            }

            if (hotReload) {
                Context context = currentApplication();
                if (context != null) installNonHealth(packageName, context, loader);
            } else {
                hookAttach(loader, (context) -> installNonHealth(packageName, context, loader));
            }
        } catch (Throwable failure) {
            Log.e(TAG, "LSP102_INSTALL_FAILED pkg=" + packageName, failure);
            logModern(Log.ERROR, "install failed for " + packageName, failure);
        }
    }

    private static void hookAttach(ClassLoader loader, ThrowingContextAction action) {
        XposedHelpers.findAndHookMethod(Application.class, "attach", Context.class, new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam param) {
                Context context = (Context) param.args[0];
                if (context == null) return;
                Context app = context.getApplicationContext() == null ? context : context.getApplicationContext();
                try {
                    action.run(app);
                } catch (Throwable failure) {
                    Log.e(TAG, "APPLICATION_ATTACH_INSTALL_FAILED", failure);
                }
            }
        });
    }

    private static void installNonHealth(String packageName, Context context, ClassLoader loader) {
        if (!installed.compareAndSet(false, true)) return;
        if ("com.heytap.mydevices".equals(packageName)) {
            try {
                MyDevicesHook.install(context, loader);
                Log.i(TAG, "DEVICE_CARD_HOOK_INSTALLED");
            } catch (Throwable skipped) {
                Log.i(TAG, "DEVICE_CARD_HOOK_SKIPPED " + skipped.getClass().getSimpleName()
                        + (skipped.getMessage() == null ? "" : " " + skipped.getMessage()));
            }
            return;
        }
        if (!HostIdentity.installed(context, HostIdentity.MI_PACKAGE)) {
            Log.i(TAG, "MI_PACKAGE_ABSENT");
            return;
        }
        try {
            MiFitnessOwnershipHook.install(context, loader);
            Log.i(TAG, "MI_OWNERSHIP_HOOK_INSTALLED");
        } catch (Throwable incompatible) {
            Log.i(TAG, "MI_OWNERSHIP_HOOK_UNAVAILABLE " + incompatible.getClass().getSimpleName());
        }
        try {
            MiFitnessImportHook.install(context, loader);
            Log.i(TAG, "IMPORT_HOOK_INSTALLED");
        } catch (Throwable incompatible) {
            Log.i(TAG, "HOST_VERSION_UNSUPPORTED");
        }
        try {
            TransportProbeHook.install(context, loader);
        } catch (Throwable incompatible) {
            Log.i(TAG, "TRANSPORT_PROBE_UNAVAILABLE");
        }
        try {
            ProtocolCaptureHook.install(context, loader);
        } catch (Throwable incompatible) {
            Log.i(TAG, "PROTOCOL_CAPTURE_UNAVAILABLE");
        }
    }

    private static Context currentApplication() {
        try {
            Object app = XposedHelpers.callStaticMethod(
                    XposedHelpers.findClass("android.app.ActivityThread", null), "currentApplication");
            if (app instanceof Context context) {
                return context.getApplicationContext() == null ? context : context.getApplicationContext();
            }
        } catch (Throwable ignored) {}
        return null;
    }

    @FunctionalInterface
    private interface ThrowingContextAction {
        void run(Context context) throws Throwable;
    }

    private static void installHealth(Context context, ClassLoader loader) {
        if (context == null || !healthInstalled.compareAndSet(false, true)) return;
        OHealthHostProfile.Profile profile = OHealthHostProfile.detect(context);
        HookResolver.resetDiagnostics();
        String profileLine = "OHEALTH_PROFILE " + profile.diagnostic();
        android.util.Log.i("OplusBandBridge", "OHEALTH_HOOKS_BEGIN " + profile.diagnostic());
        traceHealth(context, profileLine);
        try {
            OHealthWeatherHook.install(context, loader);
            android.util.Log.i("OplusBandBridge", "OHEALTH_WEATHER_HOOK_INSTALLED");
        } catch (Throwable incompatible) {
            android.util.Log.i("OplusBandBridge", "HOST_VERSION_UNSUPPORTED_OHEALTH");
        }
        try {
            OHealthDeviceHook.install(context, loader);
            android.util.Log.i("OplusBandBridge", "OHEALTH_DEVICE_HOOK_INSTALLED");
        } catch (Throwable incompatible) {
            android.util.Log.i("OplusBandBridge", "OHEALTH_DEVICE_HOOK_UNAVAILABLE");
        }
        try {
            OHealthFindPhoneHook.install(context, loader);
            android.util.Log.i("OplusBandBridge", "OHEALTH_FIND_PHONE_HOOK_INSTALLED");
        } catch (Throwable incompatible) {
            android.util.Log.i("OplusBandBridge", "OHEALTH_FIND_PHONE_HOOK_UNAVAILABLE");
        }
        try {
            OHealthMusicHook.install(context, loader);
            android.util.Log.i("OplusBandBridge", "OHEALTH_MUSIC_HOOK_INSTALLED");
        } catch (Throwable incompatible) {
            android.util.Log.i("OplusBandBridge", "OHEALTH_MUSIC_HOOK_UNAVAILABLE");
        }
        String process = Application.getProcessName();
        if (process != null && process.endsWith(":SportDaemonService")) {
            try {
                installSleepRowDelete(context, loader);
                installSleepStatReplace(loader);
                android.util.Log.i("OplusBandBridge", "OHEALTH_SLEEP_DELETE_HOOKED");
            } catch (Throwable incompatible) {
                android.util.Log.i("OplusBandBridge", "OHEALTH_SLEEP_DELETE_HOOK_UNAVAILABLE "
                        + incompatible.getClass().getSimpleName());
            }
        }
        try {
            OHealthHealthImportHook.install(context, loader);
            android.util.Log.i("OplusBandBridge", "OHEALTH_IMPORT_HOOK_INSTALLED");
        } catch (Throwable incompatible) {
            android.util.Log.i("OplusBandBridge", "OHEALTH_IMPORT_HOOK_UNAVAILABLE");
        }
        try {
            OHealthSleepHook.install(context, loader);
            android.util.Log.i("OplusBandBridge", "OHEALTH_SLEEP_HOOK_INSTALLED");
        } catch (Throwable incompatible) {
            android.util.Log.i("OplusBandBridge", "OHEALTH_SLEEP_HOOK_UNAVAILABLE");
        }
        try {
            OHealthHomeMetricHook.install(context, loader);
            android.util.Log.i("OplusBandBridge", "OHEALTH_HOME_METRIC_HOOK_INSTALLED");
        } catch (Throwable incompatible) {
            android.util.Log.i("OplusBandBridge", "OHEALTH_HOME_METRIC_HOOK_UNAVAILABLE");
        }
        try {
            OHealthNotificationAccessHook.install(context, loader);
            android.util.Log.i("OplusBandBridge", "OHEALTH_NOTIFICATION_ACCESS_HOOK_INSTALLED");
        } catch (Throwable incompatible) {
            android.util.Log.i("OplusBandBridge", "OHEALTH_NOTIFICATION_ACCESS_HOOK_UNAVAILABLE");
        }
        String dexSummary = "OHEALTH_DEX_SUMMARY " + HookResolver.diagnosticSummary();
        android.util.Log.i("OplusBandBridge", dexSummary);
        traceHealth(context, dexSummary);
    }

    private static void traceHealth(Context context, String line) {
        if (context == null || line == null || line.isBlank()) return;
        try {
            android.os.Bundle extras = new android.os.Bundle();
            extras.putString("line", line.length() > 240 ? line.substring(0, 240) : line);
            context.getContentResolver().call(
                    io.github.miam1ku.mibandoplusbridge.integration.HostNotifyProvider.URI,
                    "trace", null, extras);
        } catch (RuntimeException ignored) {
            // Diagnostic delivery must never affect host hook installation.
        }
    }

    /**
     * Table 1010 delete returns 0 and removes nothing. This process owns the database,
     * so drop rows by start time. The caller's end is inclusive.
     */
    private static void installSleepRowDelete(Context context, ClassLoader loader) {
        XposedHelpers.findAndHookMethod("com.heytap.databaseengineservice.store.SportDataStore", loader,
                "delete", "com.heytap.databaseengine.option.DataDeleteOption", new XC_MethodHook() {
                    @Override protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        Object option = param.args[0];
                        if (option == null) return;
                        if ((Integer) option.getClass().getMethod("getDataTable").invoke(option)
                                != OHealthSleepWriter.TABLE_SLEEP) return;
                        String account = (String) option.getClass().getMethod("getSsoid").invoke(option);
                        String device = (String) option.getClass().getMethod("getDeviceUniqueId").invoke(option);
                        long start = (Long) option.getClass().getMethod("getStartTime").invoke(option);
                        long end = (Long) option.getClass().getMethod("getEndTime").invoke(option);
                        if (account == null || account.isBlank() || device == null || device.isBlank()
                                || end < start) return;
                        Class<?> dbClass = Class.forName(
                                "com.heytap.databaseengineservice.db.AppDatabase", false, loader);
                        Object database = dbClass.getMethod("getInstance", Context.class).invoke(null, context);
                        Object helper = database.getClass().getMethod("getOpenHelper").invoke(database);
                        Object sqlite = helper.getClass().getMethod("getWritableDatabase").invoke(helper);
                        sqlite.getClass().getMethod("execSQL", String.class, Object[].class).invoke(sqlite,
                                new Object[] {
                                        "DELETE FROM DBSleepTable WHERE ssoid = ? AND device_unique_id = ?"
                                                + " AND start_time >= ? AND start_time <= ?",
                                        new Object[] {account, device, start, end}
                                });
                        param.setResult(0);
                    }
                });
    }

    /**
     * An API save of table 1011 passes keep-old and never replaces totals.
     * The corrected night has to overwrite the stacked summary.
     */
    private static void installSleepStatReplace(ClassLoader loader) {
        XposedHelpers.findAndHookMethod(
                "com.heytap.databaseengineservice.store.stat.SleepStatProcess", loader,
                "getUpdateData", long.class, long.class,
                "com.heytap.databaseengineservice.db.table.DBSleepDataStat",
                "com.heytap.databaseengineservice.db.table.DBSleepDataStat",
                boolean.class, new XC_MethodHook() {
                    @Override protected void beforeHookedMethod(MethodHookParam param) {
                        if (Boolean.TRUE.equals(param.args[4])) param.setResult(param.args[1]);
                    }
                });
    }


}
