// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.hook;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothSocket;
import android.content.Context;
import android.database.ContentObserver;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import io.github.miam1ku.mibandoplusbridge.integration.OwnershipProvider;
import java.io.IOException;
import java.util.Collections;
import java.util.Set;
import java.util.WeakHashMap;

/**
 * Gives the bridge exclusive access to the selected band without root shell/package disabling.
 * Only Bluetooth transports whose remote MAC equals the imported band are affected.
 */
public final class MiFitnessOwnershipHook {
    private static final String TAG = "OplusBandBridge";
    private static final Set<BluetoothSocket> SOCKETS =
            Collections.newSetFromMap(new WeakHashMap<>());
    private static final Set<BluetoothGatt> GATTS =
            Collections.newSetFromMap(new WeakHashMap<>());
    private static volatile Context hostContext;
    private static volatile ContentObserver observer;

    private MiFitnessOwnershipHook() {}

    public static synchronized void install(Context context, ClassLoader loader) {
        if (hostContext != null) return;
        hostContext = context.getApplicationContext() == null ? context : context.getApplicationContext();

        XposedBridge.hookAllMethods(BluetoothDevice.class, "createRfcommSocketToServiceRecord",
                new XC_MethodHook() {
                    @Override protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        BluetoothDevice device = (BluetoothDevice) param.thisObject;
                        if (owns(device)) param.setThrowable(new IOException("BAND_OWNED_BY_BRIDGE"));
                    }
                    @Override protected void afterHookedMethod(MethodHookParam param) {
                        if (!param.hasThrowable() && param.getResult() instanceof BluetoothSocket socket
                                && target(socket)) synchronized (SOCKETS) { SOCKETS.add(socket); }
                    }
                });

        XposedBridge.hookAllMethods(BluetoothDevice.class, "connectGatt", new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam param) {
                BluetoothDevice device = (BluetoothDevice) param.thisObject;
                if (owns(device)) param.setResult(null);
            }
            @Override protected void afterHookedMethod(MethodHookParam param) {
                if (param.getResult() instanceof BluetoothGatt gatt && target(gatt)) {
                    synchronized (GATTS) { GATTS.add(gatt); }
                    if (nativeOwnership()) closeGatt(gatt);
                }
            }
        });

        XposedBridge.hookAllMethods(BluetoothSocket.class, "connect", new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                BluetoothSocket socket = (BluetoothSocket) param.thisObject;
                if (target(socket)) {
                    synchronized (SOCKETS) { SOCKETS.add(socket); }
                    if (nativeOwnership()) param.setThrowable(new IOException("BAND_OWNED_BY_BRIDGE"));
                }
            }
        });

        XposedBridge.hookAllMethods(BluetoothGatt.class, "connect", new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam param) {
                BluetoothGatt gatt = (BluetoothGatt) param.thisObject;
                if (target(gatt)) {
                    synchronized (GATTS) { GATTS.add(gatt); }
                    if (nativeOwnership()) param.setResult(false);
                }
            }
        });

        observer = new ContentObserver(new Handler(Looper.getMainLooper())) {
            @Override public void onChange(boolean selfChange) {
                if (nativeOwnership()) releaseOfficialLinks();
            }
        };
        hostContext.getContentResolver().registerContentObserver(OwnershipProvider.URI, false, observer);
        signalOnline();
        if (nativeOwnership()) releaseOfficialLinks();
    }

    public static synchronized void detach() {
        Context context = hostContext;
        ContentObserver current = observer;
        observer = null;
        hostContext = null;
        if (context != null && current != null) {
            try { context.getContentResolver().unregisterContentObserver(current); }
            catch (RuntimeException ignored) {}
        }
        synchronized (SOCKETS) { SOCKETS.clear(); }
        synchronized (GATTS) { GATTS.clear(); }
    }

    private static boolean owns(BluetoothDevice device) {
        return device != null && target(device.getAddress()) && nativeOwnership();
    }

    private static boolean target(BluetoothSocket socket) {
        try { return socket != null && socket.getRemoteDevice() != null && target(socket.getRemoteDevice().getAddress()); }
        catch (RuntimeException unavailable) { return false; }
    }

    private static boolean target(BluetoothGatt gatt) {
        try { return gatt != null && gatt.getDevice() != null && target(gatt.getDevice().getAddress()); }
        catch (RuntimeException unavailable) { return false; }
    }

    private static boolean target(String address) {
        State state = state();
        return state != null && !state.mac.isBlank() && address != null
                && state.mac.equalsIgnoreCase(address);
    }

    private static boolean nativeOwnership() {
        State state = state();
        return state != null && state.nativeOwned;
    }

    private static State state() {
        Context context = hostContext;
        if (context == null) return null;
        try {
            Bundle reply = context.getContentResolver().call(OwnershipProvider.URI, "state", null, null);
            if (reply == null) return null;
            return new State(reply.getBoolean("native", false), reply.getString("mac", ""));
        } catch (RuntimeException unavailable) {
            return null;
        }
    }

    private static void signalOnline() {
        Context context = hostContext;
        if (context == null) return;
        try {
            Bundle extras = new Bundle();
            extras.putInt("api", 102);
            extras.putLong("versionCode", io.github.miam1ku.mibandoplusbridge.BuildConfig.VERSION_CODE);
            context.getContentResolver().call(OwnershipProvider.URI, "hookOnline", null, extras);
        } catch (RuntimeException ignored) {}
    }

    private static void releaseOfficialLinks() {
        synchronized (SOCKETS) {
            for (BluetoothSocket socket : SOCKETS) {
                try { socket.close(); } catch (IOException ignored) {}
            }
            SOCKETS.clear();
        }
        synchronized (GATTS) {
            for (BluetoothGatt gatt : GATTS) closeGatt(gatt);
            GATTS.clear();
        }
        Log.i(TAG, "MI_FITNESS_LINKS_RELEASED");
    }

    private static void closeGatt(BluetoothGatt gatt) {
        try { gatt.disconnect(); } catch (RuntimeException ignored) {}
        try { gatt.close(); } catch (RuntimeException ignored) {}
    }

    private record State(boolean nativeOwned, String mac) {}
}
