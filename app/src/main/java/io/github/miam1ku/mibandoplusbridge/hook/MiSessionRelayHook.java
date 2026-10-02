// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.hook;

import android.content.Context;
import android.database.ContentObserver;
import android.os.Binder;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Log;
import io.github.miam1ku.mibandoplusbridge.integration.CoexistRelayProvider;
import java.lang.ref.WeakReference;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import nodomain.freeyourgadget.gadgetbridge.proto.xiaomi.XiaomiProto;

/** Reuses Mi Fitness 3.59.1's authenticated WearApiCall TYPE_PROTO channel. */
public final class MiSessionRelayHook {
    private static final int TYPE_PROTO = 101;
    private static final int MAX_DRAIN = 16;
    private static final ArrayList<WeakReference<Object>> APIs = new ArrayList<>();
    private static Session session;

    private MiSessionRelayHook() {}

    public static synchronized void install(Context context, ClassLoader loader) throws Exception {
        if (session != null) return;
        Context app = context.getApplicationContext() == null ? context : context.getApplicationContext();
        Class<?> api = Class.forName("com.xiaomi.wearable.wear.api.WearApiCall", false, loader);
        Class<?> info = Class.forName("com.xiaomi.wearable.core.DeviceInfo", false, loader);
        Class<?> callback = Class.forName("com.xiaomi.wearable.core.ICallback", false, loader);
        Class<?> result = Class.forName("com.xiaomi.wearable.core.WearApiResult", false, loader);

        Constructor<?> constructor = api.getDeclaredConstructor(info);
        Method call = api.getDeclaredMethod("call", int.class, byte[].class, boolean.class,
                callback, int.class);
        Method handleData = api.getDeclaredMethod("handleData", int.class, byte[].class);
        Method isAuthConnected = api.getDeclaredMethod("isAuthConnected");

        HandlerThread thread = new HandlerThread("OplusMiSessionRelay");
        thread.start();
        Handler handler = new Handler(thread.getLooper());

        ContentObserver observer = new ContentObserver(handler) {
            @Override public void onChange(boolean selfChange) {
                handler.removeCallbacksAndMessages("relay-drain");
                handler.postAtTime(() -> drain(app, loader, callback, result, call),
                        "relay-drain", android.os.SystemClock.uptimeMillis());
            }
        };
        app.getContentResolver().registerContentObserver(CoexistRelayProvider.URI, false, observer);
        session = new Session(app, thread, handler, observer);

        XposedBridge.hookMethod(constructor, new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam param) {
                remember(param.thisObject);
                handler.post(() -> refreshOnline(app));
            }
        });
        XposedBridge.hookMethod(call, new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam param) {
                remember(param.thisObject);
                if (param.args.length > 0 && param.args[0] instanceof Integer type && type == TYPE_PROTO) {
                    handler.post(() -> refreshOnline(app));
                }
            }
        });
        XposedBridge.hookMethod(isAuthConnected, new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(param.getResult())) {
                    remember(param.thisObject);
                    handler.post(() -> refreshOnline(app));
                }
            }
        });
        XposedBridge.hookMethod(handleData, new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam param) {
                if (param.args.length < 2 || !(param.args[0] instanceof Integer type)
                        || type != TYPE_PROTO || !(param.args[1] instanceof byte[] payload)
                        || !target(param.thisObject)) return;
                final XiaomiProto.Command command;
                try {
                    command = XiaomiProto.Command.parseFrom(payload);
                } catch (Exception ignored) {
                    return;
                }
                if (!interesting(command)) return;
                byte[] snapshot = payload.clone();
                handler.post(() -> publishEvent(app, param.thisObject, snapshot));
            }
        });

        handler.post(() -> refreshOnline(app));
        Log.i("OplusBandBridge", "MI_SESSION_RELAY_READY type=101");
    }

    public static synchronized void detach() {
        Session current = session;
        session = null;
        synchronized (APIs) { APIs.clear(); }
        if (current == null) return;
        try { current.context.getContentResolver().unregisterContentObserver(current.observer); }
        catch (RuntimeException ignored) { }
        current.handler.removeCallbacksAndMessages(null);
        current.thread.quit();
    }

    public static void stateChanged() {
        Session current = session;
        if (current != null) current.handler.post(() -> refreshOnline(current.context));
    }

    private static void remember(Object api) {
        if (api == null) return;
        synchronized (APIs) {
            Iterator<WeakReference<Object>> it = APIs.iterator();
            while (it.hasNext()) {
                Object value = it.next().get();
                if (value == null) it.remove();
                else if (value == api) return;
            }
            while (APIs.size() >= 8) APIs.remove(0);
            APIs.add(new WeakReference<>(api));
        }
    }

    private static Object activeApi() {
        synchronized (APIs) {
            Iterator<WeakReference<Object>> it = APIs.iterator();
            while (it.hasNext()) {
                Object api = it.next().get();
                if (api == null) { it.remove(); continue; }
                if (!target(api)) continue;
                try {
                    if (Boolean.TRUE.equals(XposedHelpers.callMethod(api, "isAuthConnected"))) return api;
                } catch (Throwable ignored) { }
            }
        }
        return null;
    }

    private static boolean target(Object api) {
        if (api == null || !MiFitnessOwnershipHook.coexistMode()) return false;
        String selected = MiFitnessOwnershipHook.selectedAddress();
        if (selected.isBlank()) return false;
        try {
            Object info = XposedHelpers.callMethod(api, "getDeviceInfo");
            String address = String.valueOf(XposedHelpers.callMethod(info, "getAddress"));
            return selected.equalsIgnoreCase(address);
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static void refreshOnline(Context context) {
        Object api = activeApi();
        if (api == null) return;
        try {
            Object info = XposedHelpers.callMethod(api, "getDeviceInfo");
            String address = String.valueOf(XposedHelpers.callMethod(info, "getAddress"));
            Bundle online = new Bundle();
            online.putString("address", address);
            context.getContentResolver().call(CoexistRelayProvider.URI, "online", null, online);
        } catch (Throwable ignored) { }
    }

    private static void drain(Context context, ClassLoader loader, Class<?> callbackType,
            Class<?> resultType, Method call) {
        Object api = activeApi();
        if (api == null) return;
        String address;
        try {
            Object info = XposedHelpers.callMethod(api, "getDeviceInfo");
            address = String.valueOf(XposedHelpers.callMethod(info, "getAddress"));
        } catch (Throwable unavailable) {
            return;
        }
        for (int i = 0; i < MAX_DRAIN; i++) {
            Bundle poll = new Bundle();
            poll.putString("address", address);
            Bundle request;
            try {
                request = context.getContentResolver().call(CoexistRelayProvider.URI, "poll", null, poll);
            } catch (RuntimeException unavailable) {
                return;
            }
            if (request == null || !"REQUEST".equals(request.getString("status"))) return;
            long id = request.getLong("requestId", -1);
            byte[] payload = request.getByteArray("payload");
            boolean needResponse = request.getBoolean("needResponse", false);
            int timeout = request.getInt("timeoutMs", 5_000);
            if (id < 0 || payload == null) continue;
            try {
                Object callback = callback(loader, callbackType, resultType, context, id);
                Object task = call.invoke(api, TYPE_PROTO, payload, needResponse, callback, timeout);
                if (!needResponse) complete(context, id, "ENQUEUED",
                        task instanceof Number number ? number.intValue() : 0, null);
            } catch (Throwable failure) {
                complete(context, id, "FAILED", -1, null);
            } finally {
                java.util.Arrays.fill(payload, (byte) 0);
            }
        }
    }

    private static Object callback(ClassLoader loader, Class<?> callbackType, Class<?> resultType,
            Context context, long id) {
        Binder binder = new Binder();
        return Proxy.newProxyInstance(loader, new Class[]{callbackType}, (proxy, method, args) -> {
            return switch (method.getName()) {
                case "asBinder" -> binder;
                case "onCallback" -> {
                    int code = -1;
                    byte[] data = null;
                    if (args != null && args.length == 1 && args[0] != null
                            && resultType.isInstance(args[0])) {
                        try { code = ((Number) XposedHelpers.callMethod(args[0], "a")).intValue(); }
                        catch (Throwable ignored) { }
                        try {
                            Object raw = XposedHelpers.callMethod(args[0], "c");
                            if (raw instanceof byte[] bytes) data = bytes.clone();
                        } catch (Throwable ignored) { }
                    }
                    complete(context, id, code == 0 ? "OK" : "RESULT", code, data);
                    yield null;
                }
                case "toString" -> "OplusBandRelayCallback";
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == (args == null || args.length == 0 ? null : args[0]);
                default -> null;
            };
        });
    }

    private static void complete(Context context, long id, String status, int code, byte[] data) {
        try {
            Bundle result = new Bundle();
            result.putLong("requestId", id);
            result.putString("status", status);
            result.putInt("resultCode", code);
            if (data != null && data.length <= CoexistRelayProvider.MAX_PAYLOAD) result.putByteArray("payload", data);
            context.getContentResolver().call(CoexistRelayProvider.URI, "complete", null, result);
        } catch (RuntimeException ignored) { }
        finally { if (data != null) java.util.Arrays.fill(data, (byte) 0); }
    }

    private static void publishEvent(Context context, Object api, byte[] payload) {
        try {
            if (!target(api)) return;
            Object info = XposedHelpers.callMethod(api, "getDeviceInfo");
            Bundle event = new Bundle();
            event.putString("address", String.valueOf(XposedHelpers.callMethod(info, "getAddress")));
            event.putByteArray("payload", payload);
            context.getContentResolver().call(CoexistRelayProvider.URI, "event", null, event);
        } catch (Throwable ignored) { }
        finally { java.util.Arrays.fill(payload, (byte) 0); }
    }

    private static boolean interesting(XiaomiProto.Command command) {
        int type = command.getType(), subtype = command.getSubtype();
        if (type == 10) return true;
        if (type == 18) return subtype == 0 || subtype == 2;
        if (type == 2) return subtype == 17 || subtype == 43 || subtype == 109 || subtype == 110;
        if (type == 7) return subtype == 16;
        return type == 17 && subtype == 16;
    }

    private record Session(Context context, HandlerThread thread, Handler handler, ContentObserver observer) {}
}
