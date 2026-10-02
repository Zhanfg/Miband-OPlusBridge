// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.hook;

import android.content.Context;
import android.os.Bundle;
import android.util.Log;
import io.github.miam1ku.mibandoplusbridge.data.AuthToken;
import io.github.miam1ku.mibandoplusbridge.integration.CredentialProvider;
import java.lang.reflect.Method;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Captures only the user-selected Mi Fitness device during the short import window.
 *
 * The DeviceInfo object hook is the authoritative path. The historical
 * DeviceModelExtKt.convert() hook is retained only as a fast path and for access
 * to legacy source-side token fields.
 */
public final class MiFitnessImportHook {
    private static final String TAG = "OplusBandBridge";
    private static final AtomicBoolean pending = new AtomicBoolean();
    private static final ThreadLocal<Boolean> capturing = ThreadLocal.withInitial(() -> false);
    private static volatile ExecutorService writer;

    private MiFitnessImportHook() {}

    public static synchronized void install(Context context, ClassLoader loader) throws Exception {
        if (writer != null && !writer.isShutdown()) return;
        ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
            Thread thread = new Thread(r, "OplusBandImport");
            thread.setDaemon(true);
            return thread;
        });
        writer = executor;

        Class<?> infoClass = resolveDeviceInfo(context, loader);
        Method getAddress = HookResolver.resolveNamedMethod(infoClass, "getAddress", 0, String.class);
        XposedBridge.hookMethod(getAddress, new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam param) {
                if (param.hasThrowable() || param.thisObject == null || capturing.get()) return;
                Object result = param.getResult();
                capture(context, param.thisObject, null, result instanceof String value ? value : null);
            }
        });

        boolean legacyConvert = installLegacyConvert(context, loader, infoClass);
        signalOnline(context, legacyConvert ? "DEVICE_INFO+CONVERT" : "DEVICE_INFO");
        Log.i(TAG, "MI_IMPORT_HOOK_READY mode=" + (legacyConvert ? "DEVICE_INFO+CONVERT" : "DEVICE_INFO")
                + " info=" + infoClass.getName());
    }

    public static synchronized void detach() {
        ExecutorService current = writer;
        writer = null;
        pending.set(false);
        capturing.remove();
        if (current != null) current.shutdownNow();
    }

    private static Class<?> resolveDeviceInfo(Context context, ClassLoader loader)
            throws ClassNotFoundException {
        return HookResolver.resolveClassByMembers(context, loader,
                "com.xiaomi.wearable.core.DeviceInfo", "com.xiaomi.wearable.", null,
                new String[]{"getAddress", "getModel", "getUserId", "getRegion",
                        "getType", "getAccessType"}, new String[0]);
    }

    private static boolean installLegacyConvert(Context context, ClassLoader loader, Class<?> infoClass) {
        try {
            Class<?> source = Class.forName(
                    "com.xiaomi.fitness.device.manager.export.bean.WearableDeviceInfo", false, loader);
            Class<?> owner = Class.forName("com.xiaomi.fit.device.extensions.DeviceModelExtKt", false, loader);
            Method convert = owner.getDeclaredMethod("convert", source);
            if (!infoClass.isAssignableFrom(convert.getReturnType())) return false;
            XposedBridge.hookMethod(convert, new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    if (param.hasThrowable() || param.getResult() == null || capturing.get()) return;
                    capture(context, param.getResult(), param.args.length == 0 ? null : param.args[0], null);
                }
            });
            return true;
        } catch (Throwable moved) {
            Log.i(TAG, "MI_IMPORT_CONVERT_FALLBACK " + moved.getClass().getSimpleName());
            return false;
        }
    }

    private static void capture(Context context, Object info, Object source, String observedAddress) {
        if (info == null || capturing.get()) return;
        capturing.set(true);
        boolean dispatched = false;
        try {
            Bundle request = context.getContentResolver().call(
                    CredentialProvider.URI, "getImportRequest", null, null);
            if (request == null || !"IMPORT_WINDOW_OPEN".equals(request.getString("status"))) return;

            String address = observedAddress;
            if (address == null || address.isBlank()) address = string(info, "getAddress");
            if (address == null || !address.toUpperCase(Locale.ROOT)
                    .equals(request.getString("address"))) return;
            if (!pending.compareAndSet(false, true)) return;

            Bundle binding = new Bundle();
            binding.putString("nonce", request.getString("nonce"));
            binding.putString("address", request.getString("address"));
            put(binding, "did", string(info, "getDid"));
            put(binding, "model", string(info, "getModel"));
            put(binding, "productId", string(info, "getProductId"));
            put(binding, "userId", string(info, "getUserId"));
            put(binding, "region", string(info, "getRegion"));
            put(binding, "appDeviceId", string(info, "getAppDeviceId"));
            put(binding, "token", string(info, "getToken"));
            put(binding, "firmware", string(info, "getFirmwareVersion"));
            put(binding, "oob", string(info, "getOob"));
            put(binding, "deviceName", string(info, "getDeviceName"));

            fillTokenFromSource(binding, source, info);
            Integer type = integer(info, "getType");
            Integer accessType = integer(info, "getAccessType");
            if (type != null) binding.putInt("type", type);
            if (accessType != null) binding.putInt("accessType", accessType);

            Object privateUUID = call(info, "getPrivateUUID");
            if (privateUUID != null) {
                Bundle uuids = new Bundle();
                for (String key : new String[]{"fitness", "mass", "otaRX", "otaTX",
                        "protoRX", "protoTX", "service", "voice"}) {
                    String getter = "get" + Character.toUpperCase(key.charAt(0)) + key.substring(1);
                    put(uuids, key, string(privateUUID, getter));
                }
                if (!uuids.isEmpty()) binding.putBundle("privateUUID", uuids);
            }

            ExecutorService queue = writer;
            if (queue == null || queue.isShutdown()) {
                pending.set(false);
                return;
            }
            queue.execute(() -> {
                try {
                    Bundle result = context.getContentResolver().call(
                            CredentialProvider.URI, "importBinding", null, binding);
                    Log.i(TAG, "MI_IMPORT_CAPTURED status="
                            + (result == null ? "null" : result.getString("status", "unknown")));
                } catch (RuntimeException rejected) {
                    Log.i(TAG, "MI_IMPORT_REJECTED");
                } finally {
                    binding.clear();
                    pending.set(false);
                }
            });
            dispatched = true;
        } catch (RejectedExecutionException stopped) {
            Log.i(TAG, "MI_IMPORT_QUEUE_STOPPED");
        } catch (Throwable incompatible) {
            Log.i(TAG, "MI_IMPORT_CAPTURE_FAILED " + incompatible.getClass().getSimpleName());
        } finally {
            capturing.set(false);
            if (!dispatched && pending.get()) pending.set(false);
        }
    }

    private static void signalOnline(Context context, String mode) {
        try {
            Bundle extras = new Bundle();
            extras.putString("mode", mode);
            context.getContentResolver().call(CredentialProvider.URI, "importHookOnline", null, extras);
        } catch (RuntimeException ignored) { }
    }

    /** convert() picks one of authKey/token/appToken/encryptKey; some bands leave getToken() empty. */
    private static void fillTokenFromSource(Bundle binding, Object source, Object converted) {
        if (AuthToken.hex32(binding.getString("token"))) return;
        Object device = call(source, "getDevice");
        if (device == null) device = field(source, "device");
        Object detail = call(device, "getDetail");
        String token = AuthToken.firstHex32(
                binding.getString("token"),
                string(converted, "getToken"),
                string(detail, "getEncryptKey"),
                string(detail, "getToken"),
                string(detail, "getAuthKey"),
                string(detail, "getAppToken"));
        if (AuthToken.hex32(token)) binding.putString("token", token);
    }

    private static void put(Bundle out, String key, String value) {
        if (value != null) out.putString(key, value);
    }

    private static Object call(Object target, String getter) {
        if (target == null) return null;
        try {
            return XposedHelpers.callMethod(target, getter);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static String string(Object target, String getter) {
        Object value = call(target, getter);
        return value instanceof String text ? text : null;
    }

    private static Integer integer(Object target, String getter) {
        Object value = call(target, getter);
        return value instanceof Number number ? number.intValue() : null;
    }

    private static Object field(Object target, String name) {
        if (target == null) return null;
        try {
            return XposedHelpers.getObjectField(target, name);
        } catch (Throwable ignored) {
            return null;
        }
    }
}
