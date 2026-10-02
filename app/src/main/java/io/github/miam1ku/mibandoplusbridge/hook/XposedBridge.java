// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.hook;

import android.util.Log;
import io.github.libxposed.api.XposedInterface;
import java.lang.reflect.Executable;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/** Modern libxposed-backed replacement for the tiny legacy bridge surface this project used. */
public final class XposedBridge {
    private static final String TAG = "OplusBandBridge";

    private XposedBridge() {}

    public static void hookMethod(Member member, XC_MethodHook callback) {
        if (!(member instanceof Executable executable)) {
            throw new IllegalArgumentException("HOOK_MEMBER_NOT_EXECUTABLE");
        }
        EntryPoint.installHook(executable, callback);
    }

    public static List<Object> hookAllMethods(Class<?> type, String name, XC_MethodHook callback) {
        List<Object> installed = new ArrayList<>();
        if (type == null || name == null) return installed;
        for (Method method : type.getDeclaredMethods()) {
            if (!name.equals(method.getName())) continue;
            method.setAccessible(true);
            EntryPoint.installHook(method, callback);
            installed.add(method);
        }
        return installed;
    }

    static Object dispatch(Executable executable, XC_MethodHook callback,
                           XposedInterface.Chain chain) throws Throwable {
        XC_MethodHook.MethodHookParam param = new XC_MethodHook.MethodHookParam();
        param.method = executable;
        param.thisObject = chain.getThisObject();
        param.args = chain.getArgs().toArray();

        try {
            callback.beforeHookedMethod(param);
        } catch (Throwable callbackFailure) {
            logCallback("before", executable, callbackFailure);
        }

        if (!param.returnEarly()) {
            try {
                param.resultFromOriginal(chain.proceed(param.args));
            } catch (Throwable originalFailure) {
                param.throwableFromOriginal(originalFailure);
            }
            param.thisObject = chain.getThisObject();
        }

        try {
            callback.afterHookedMethod(param);
        } catch (Throwable callbackFailure) {
            logCallback("after", executable, callbackFailure);
        }

        if (param.hasThrowable()) throw param.getThrowable();
        return param.getResult();
    }

    private static void logCallback(String phase, Executable executable, Throwable failure) {
        Log.e(TAG, "HOOK_CALLBACK_" + phase.toUpperCase() + " " + executable.toGenericString(), failure);
        EntryPoint.logModern(Log.ERROR, "hook " + phase + " failed: " + executable.toGenericString(), failure);
    }

    public static void log(String text) {
        Log.i(TAG, text == null ? "" : text);
        EntryPoint.logModern(Log.INFO, text == null ? "" : text, null);
    }
}
