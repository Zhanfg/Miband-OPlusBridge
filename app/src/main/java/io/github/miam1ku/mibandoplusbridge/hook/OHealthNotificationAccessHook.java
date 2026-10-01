// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.hook;

import android.app.NotificationManager;
import android.content.ComponentName;
import android.content.Context;
import android.util.Log;
import java.lang.reflect.Method;
import java.util.LinkedHashSet;
import java.util.Set;

/** OHealth's listener API stays false on this ROM and then disable/enable-loops the service. */
public final class OHealthNotificationAccessHook {
    private static final String UTIL = "com.heytap.health.watch.notification.NotificationListenerUtil";
    private static final String COMPANION = UTIL + "$Companion";
    private static final String LISTENER =
            "com.heytap.health.watch.commonnotification.HeytapNotificationListenerService";
    private static final String COMPONENT = "com.heytap.health/" + LISTENER;

    private OHealthNotificationAccessHook() {}

    public static void install(Context hostContext, ClassLoader loader) throws ClassNotFoundException {
        XC_MethodHook grant = new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(param.getResult())) return;
                Context context = contextArg(param);
                if (context != null && granted(context)) param.setResult(true);
            }
        };
        Set<Class<?>> utilities = new LinkedHashSet<>();
        try {
            Class<?> companion = Class.forName(COMPANION, false, loader);
            XposedBridge.hookAllMethods(companion, "isNotificationListenerEnabled", grant);
            utilities.add(companion);
        } catch (ClassNotFoundException moved) {
            Log.i("OplusBandBridge", "OHEALTH_NOTIFICATION_COMPANION_MOVED");
        }
        try {
            Class<?> util = Class.forName(UTIL, false, loader);
            XposedBridge.hookAllMethods(util, "isNotificationListenerEnabled", grant);
            utilities.add(util);
        } catch (ClassNotFoundException moved) {
            Log.i("OplusBandBridge", "OHEALTH_NOTIFICATION_UTIL_MOVED");
        }
        if (utilities.isEmpty()) {
            Method anchored = null;
            for (Class<?>[] signature : new Class<?>[][] {
                    {Context.class}, new Class<?>[0]}) {
                try {
                    anchored = DexAnchors.resolveAnchoredMethod(hostContext, loader,
                            "com.heytap.health.watch.notification.__MovedNotificationListenerUtil",
                            "isNotificationListenerEnabled",
                            java.util.List.of("enabled_notification_listeners"),
                            null, boolean.class, signature);
                    break;
                } catch (Throwable ignored) { }
            }
            if (anchored != null) {
                XposedBridge.hookMethod(anchored, grant);
                utilities.add(anchored.getDeclaringClass());
                Log.i("OplusBandBridge", "OHEALTH_NOTIFICATION_DEX_ANCHOR "
                        + anchored.getDeclaringClass().getName() + "#" + anchored.getName());
            }
        }
        XC_MethodHook keep = new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam param) {
                Context context = contextArg(param);
                boolean real = context != null && granted(context);
                Log.i("OplusBandBridge", "OHEALTH_NOTIFICATION_LISTENER granted=" + real);
                // A granted listener that the ROM reports as off gets disable/enable-looped.
                // An actually missing listener must still be allowed to start.
                if (real) param.setResult(null);
            }
        };
        for (Class<?> utility : utilities) {
            XposedBridge.hookAllMethods(utility, "runNotificationService", keep);
            XposedBridge.hookAllMethods(utility, "stopNotificationService", keep);
        }
        XposedHelpers.findAndHookMethod(NotificationManager.class, "isNotificationListenerAccessGranted",
                ComponentName.class, new XC_MethodHook() {
                    @Override protected void afterHookedMethod(MethodHookParam param) {
                        if (Boolean.TRUE.equals(param.getResult())) return;
                        if (!(param.args[0] instanceof ComponentName name)) return;
                        if (!LISTENER.equals(name.getClassName())) return;
                        Context context = contextArg(param);
                        if (context != null && granted(context)) param.setResult(true);
                    }
                });
        Class<?> item = Class.forName(
                "com.heytap.health.device.tab.itemview.wearable.MenuNotificationItem", false, loader);
        XposedBridge.hookAllMethods(item, "initData", new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam param) {
                try {
                    Object controller = XposedHelpers.callMethod(param.thisObject, "getController");
                    Object label = XposedHelpers.callMethod(param.thisObject, "getMTvRight");
                    XposedHelpers.callMethod(label, "setText", "");
                } catch (Throwable ignored) { }
            }
        });
    }

    private static Context contextArg(XC_MethodHook.MethodHookParam param) {
        if (param.thisObject instanceof Context context) return context;
        if (param.args != null) {
            for (Object arg : param.args) {
                if (arg instanceof Context context) return context;
            }
        }
        try {
            Object app = XposedHelpers.callStaticMethod(
                    XposedHelpers.findClass("android.app.ActivityThread", null), "currentApplication");
            return app instanceof Context context ? context : null;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static boolean granted(Context context) {
        String enabled = android.provider.Settings.Secure.getString(context.getContentResolver(),
                "enabled_notification_listeners");
        if (enabled == null || enabled.isBlank()) return false;
        ComponentName component = ComponentName.unflattenFromString(COMPONENT);
        String flat = component == null ? COMPONENT : component.flattenToString();
        String shortName = component == null ? COMPONENT : component.flattenToShortString();
        for (String item : enabled.split(":")) {
            if (flat.equals(item) || shortName.equals(item) || COMPONENT.equals(item)) return true;
        }
        return false;
    }
}
