// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.hook;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

/**
 * Reflection helpers with the subset of legacy XposedHelpers used by this module.
 * Keeping this local avoids a second framework dependency under API 102.
 */
public final class XposedHelpers {
    private XposedHelpers() {}

    public static Class<?> findClass(String name, ClassLoader loader) {
        try {
            return Class.forName(name, false, loader == null ? XposedHelpers.class.getClassLoader() : loader);
        } catch (ClassNotFoundException error) {
            throw new IllegalStateException("CLASS_NOT_FOUND " + name, error);
        }
    }

    public static void findAndHookMethod(String className, ClassLoader loader, String name, Object... spec) {
        findAndHookMethod(findClass(className, loader), name, spec);
    }

    public static void findAndHookMethod(Class<?> type, String name, Object... spec) {
        if (spec.length == 0 || !(spec[spec.length - 1] instanceof XC_MethodHook callback)) {
            throw new IllegalArgumentException("HOOK_CALLBACK_REQUIRED");
        }
        ClassLoader loader = type.getClassLoader();
        Class<?>[] parameters = new Class<?>[spec.length - 1];
        for (int i = 0; i < parameters.length; i++) {
            Object value = spec[i];
            if (value instanceof Class<?> clazz) parameters[i] = clazz;
            else if (value instanceof String className) parameters[i] = findClass(className, loader);
            else throw new IllegalArgumentException("HOOK_PARAMETER_TYPE_REQUIRED");
        }
        Method method = declaredMethod(type, name, parameters);
        method.setAccessible(true);
        XposedBridge.hookMethod(method, callback);
    }

    public static Object callMethod(Object target, String name, Object... args) {
        if (target == null) throw new NullPointerException("CALL_TARGET_NULL " + name);
        try {
            Method method = bestMethod(target.getClass(), name, args, false);
            method.setAccessible(true);
            return method.invoke(target, args);
        } catch (ReflectiveOperationException error) {
            throw reflect("CALL_FAILED " + target.getClass().getName() + "#" + name, error);
        }
    }

    public static Object callStaticMethod(Class<?> type, String name, Object... args) {
        try {
            Method method = bestMethod(type, name, args, true);
            method.setAccessible(true);
            return method.invoke(null, args);
        } catch (ReflectiveOperationException error) {
            throw reflect("STATIC_CALL_FAILED " + type.getName() + "#" + name, error);
        }
    }

    public static Object newInstance(Class<?> type, Object... args) {
        try {
            Constructor<?> constructor = bestConstructor(type, args);
            constructor.setAccessible(true);
            return constructor.newInstance(args);
        } catch (ReflectiveOperationException error) {
            throw reflect("CONSTRUCTOR_FAILED " + type.getName(), error);
        }
    }

    public static Object getObjectField(Object target, String name) {
        try {
            Field field = field(target.getClass(), name);
            field.setAccessible(true);
            return field.get(target);
        } catch (ReflectiveOperationException error) {
            throw reflect("FIELD_READ_FAILED " + name, error);
        }
    }

    public static Object getStaticObjectField(Class<?> type, String name) {
        try {
            Field field = field(type, name);
            field.setAccessible(true);
            return field.get(null);
        } catch (ReflectiveOperationException error) {
            throw reflect("STATIC_FIELD_READ_FAILED " + name, error);
        }
    }

    public static int getIntField(Object target, String name) {
        Object value = getObjectField(target, name);
        return ((Number) value).intValue();
    }

    public static void setIntField(Object target, String name, int value) {
        setField(target, name, value);
    }

    public static void setBooleanField(Object target, String name, boolean value) {
        setField(target, name, value);
    }

    private static void setField(Object target, String name, Object value) {
        try {
            Field field = field(target.getClass(), name);
            field.setAccessible(true);
            field.set(target, value);
        } catch (ReflectiveOperationException error) {
            throw reflect("FIELD_WRITE_FAILED " + name, error);
        }
    }

    private static Method declaredMethod(Class<?> type, String name, Class<?>[] parameters) {
        Class<?> cursor = type;
        while (cursor != null) {
            try { return cursor.getDeclaredMethod(name, parameters); }
            catch (NoSuchMethodException ignored) { cursor = cursor.getSuperclass(); }
        }
        throw new IllegalStateException("METHOD_NOT_FOUND " + type.getName() + "#" + name);
    }

    private static Method bestMethod(Class<?> type, String name, Object[] args, boolean requireStatic)
            throws NoSuchMethodException {
        Method best = null;
        int bestScore = Integer.MIN_VALUE;
        for (Class<?> cursor = type; cursor != null; cursor = cursor.getSuperclass()) {
            for (Method method : cursor.getDeclaredMethods()) {
                if (!name.equals(method.getName()) || method.getParameterCount() != args.length) continue;
                if (requireStatic != Modifier.isStatic(method.getModifiers())) continue;
                int score = score(method.getParameterTypes(), args);
                if (score > bestScore) {
                    best = method;
                    bestScore = score;
                }
            }
        }
        if (best == null || bestScore < 0) throw new NoSuchMethodException(type.getName() + "#" + name);
        return best;
    }

    private static Constructor<?> bestConstructor(Class<?> type, Object[] args) throws NoSuchMethodException {
        Constructor<?> best = null;
        int bestScore = Integer.MIN_VALUE;
        for (Constructor<?> constructor : type.getDeclaredConstructors()) {
            if (constructor.getParameterCount() != args.length) continue;
            int score = score(constructor.getParameterTypes(), args);
            if (score > bestScore) {
                best = constructor;
                bestScore = score;
            }
        }
        if (best == null || bestScore < 0) throw new NoSuchMethodException(type.getName());
        return best;
    }

    private static int score(Class<?>[] parameters, Object[] args) {
        int score = 0;
        for (int i = 0; i < parameters.length; i++) {
            Class<?> parameter = wrap(parameters[i]);
            Object arg = args[i];
            if (arg == null) {
                if (parameters[i].isPrimitive()) return -1;
                continue;
            }
            Class<?> actual = arg.getClass();
            if (parameter == actual) score += 4;
            else if (parameter.isAssignableFrom(actual)) score += 2;
            else return -1;
        }
        return score;
    }

    private static Class<?> wrap(Class<?> type) {
        if (!type.isPrimitive()) return type;
        if (type == boolean.class) return Boolean.class;
        if (type == byte.class) return Byte.class;
        if (type == short.class) return Short.class;
        if (type == int.class) return Integer.class;
        if (type == long.class) return Long.class;
        if (type == float.class) return Float.class;
        if (type == double.class) return Double.class;
        if (type == char.class) return Character.class;
        return type;
    }

    private static Field field(Class<?> type, String name) throws NoSuchFieldException {
        for (Class<?> cursor = type; cursor != null; cursor = cursor.getSuperclass()) {
            try { return cursor.getDeclaredField(name); }
            catch (NoSuchFieldException ignored) {}
        }
        throw new NoSuchFieldException(type.getName() + "#" + name);
    }

    private static RuntimeException reflect(String message, ReflectiveOperationException error) {
        Throwable cause = error instanceof java.lang.reflect.InvocationTargetException
                && ((java.lang.reflect.InvocationTargetException) error).getCause() != null
                ? ((java.lang.reflect.InvocationTargetException) error).getCause() : error;
        if (cause instanceof RuntimeException runtime) return runtime;
        return new IllegalStateException(message, cause);
    }
}
