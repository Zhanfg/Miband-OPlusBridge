// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.hook;

import android.content.Context;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * Version-adaptive resolver for vendor hooks.
 *
 * DexAnchors remains the byte parser. This layer resolves parsed references
 * against the current host ClassLoader and always fails closed on ambiguity.
 */
final class HookResolver {
    private static final int CACHE_LIMIT = 16;
    private static final LinkedHashMap<String, List<String>> CLASS_CACHE =
            new LinkedHashMap<>(16, 0.75f, true);
    private static final LinkedHashMap<String, List<DexAnchors.MethodRef>> ANCHOR_CACHE =
            new LinkedHashMap<>(16, 0.75f, true);

    private HookResolver() {}

    static Class<?> resolveClass(Context context, ClassLoader loader, String stableName,
            String packagePrefix, Class<?>... signature) throws ClassNotFoundException {
        return resolveClassBySignatures(context, loader, stableName, packagePrefix,
                new Class<?>[][] {signature});
    }

    static Class<?> resolveClassBySignatures(Context context, ClassLoader loader, String stableName,
            String packagePrefix, Class<?>[]... signatures) throws ClassNotFoundException {
        try {
            return Class.forName(stableName, false, loader);
        } catch (ClassNotFoundException missing) {
            Class<?> found = null;
            for (String apk : apkPaths(context)) {
                try {
                    for (String name : cachedClassNames(apk)) {
                        if (packagePrefix != null && !name.startsWith(packagePrefix)) continue;
                        if (name.indexOf('$') >= 0) continue;
                        Class<?> candidate;
                        try {
                            candidate = Class.forName(name, false, loader);
                        } catch (Throwable unavailable) {
                            continue;
                        }
                        if (!declaresSignatures(candidate, signatures)) continue;
                        if (found != null && found != candidate) {
                            throw new IllegalStateException("DEX_CLASS_SIGNATURE_AMBIGUOUS");
                        }
                        found = candidate;
                    }
                } catch (IOException ignored) { }
            }
            if (found != null) return found;
            throw missing;
        }
    }

    static Class<?> resolveClassByMembers(Context context, ClassLoader loader, String stableName,
            String packagePrefix, Class<?> requiredSuper, String[] methodNames, String[] fieldNames)
            throws ClassNotFoundException {
        return resolveClassByMembers(context, loader, stableName, packagePrefix, requiredSuper,
                methodNames, fieldNames, false);
    }

    /**
     * Resolve a moved vendor class from stable member names.
     * Class loading is initialization-free and ambiguity always fails closed.
     */
    static Class<?> resolveClassByMembers(Context context, ClassLoader loader, String stableName,
            String packagePrefix, Class<?> requiredSuper, String[] methodNames, String[] fieldNames,
            boolean allowInner) throws ClassNotFoundException {
        try {
            return Class.forName(stableName, false, loader);
        } catch (ClassNotFoundException missing) {
            Class<?> found = null;
            for (String apk : apkPaths(context)) {
                try {
                    for (String name : cachedClassNames(apk)) {
                        if (packagePrefix != null && !name.startsWith(packagePrefix)) continue;
                        if (!allowInner && name.indexOf('$') >= 0) continue;
                        Class<?> candidate;
                        try {
                            candidate = Class.forName(name, false, loader);
                        } catch (Throwable unavailable) {
                            continue;
                        }
                        if (requiredSuper != null && !requiredSuper.isAssignableFrom(candidate)) continue;
                        if (!hasMethods(candidate, methodNames) || !hasFields(candidate, fieldNames)) continue;
                        if (found != null && found != candidate) {
                            throw new IllegalStateException("DEX_CLASS_MEMBER_AMBIGUOUS " + stableName);
                        }
                        found = candidate;
                    }
                } catch (IOException ignored) { }
            }
            if (found != null) return found;
            throw missing;
        }
    }

    static Method resolveMethod(Class<?> owner, String stableName, Class<?> returnType,
            Class<?>... parameters) throws NoSuchMethodException {
        for (Class<?> cursor = owner; cursor != null; cursor = cursor.getSuperclass()) {
            try {
                Method method = cursor.getDeclaredMethod(stableName, parameters);
                if (returnType == null || method.getReturnType() == returnType) {
                    method.setAccessible(true);
                    return method;
                }
            } catch (NoSuchMethodException ignored) { }
        }
        Method found = null;
        for (Class<?> cursor = owner; cursor != null; cursor = cursor.getSuperclass()) {
            for (Method method : cursor.getDeclaredMethods()) {
                if (returnType != null && method.getReturnType() != returnType) continue;
                if (!sameParameters(method.getParameterTypes(), parameters)) continue;
                if (found != null && !found.equals(method)) {
                    throw new NoSuchMethodException("DEX_METHOD_SIGNATURE_AMBIGUOUS "
                            + owner.getName() + "#" + stableName);
                }
                found = method;
            }
        }
        if (found == null) throw new NoSuchMethodException(owner.getName() + "#" + stableName);
        found.setAccessible(true);
        return found;
    }

    static Method resolveAnchoredMethod(Context context, ClassLoader loader,
            String stableClass, String stableMethod, String literal,
            Class<?> ownerSuper, Class<?> returnType, Class<?>... parameters) throws Exception {
        return resolveAnchoredMethod(context, loader, stableClass, stableMethod,
                List.of(literal), ownerSuper, returnType, parameters);
    }

    static Method resolveAnchoredMethod(Context context, ClassLoader loader,
            String stableClass, String stableMethod, List<String> literals,
            Class<?> ownerSuper, Class<?> returnType, Class<?>... parameters) throws Exception {
        try {
            Class<?> owner = Class.forName(stableClass, false, loader);
            return resolveMethod(owner, stableMethod, returnType, parameters);
        } catch (ReflectiveOperationException moved) {
            LinkedHashMap<String, Candidate> candidates = new LinkedHashMap<>();
            for (String literal : literals) {
                if (literal == null || literal.isBlank()) continue;
                HashSet<String> counted = new HashSet<>();
                for (String apk : apkPaths(context)) {
                    for (DexAnchors.MethodRef ref : cachedMethods(apk, literal)) {
                        Class<?> owner;
                        try {
                            owner = Class.forName(binaryName(ref.classDescriptor()), false, loader);
                        } catch (Throwable unavailable) {
                            continue;
                        }
                        if (ownerSuper != null && !ownerSuper.isAssignableFrom(owner)) continue;
                        Method method;
                        try {
                            method = owner.getDeclaredMethod(ref.name(),
                                    descriptorClasses(ref.parameters(), loader));
                        } catch (Throwable unavailable) {
                            continue;
                        }
                        if (returnType != null && method.getReturnType() != returnType) continue;
                        if (!sameParameters(method.getParameterTypes(), parameters)) continue;
                        String id = method.toGenericString();
                        Candidate candidate = candidates.computeIfAbsent(id,
                                ignored -> new Candidate(method));
                        if (counted.add(id)) candidate.score++;
                    }
                }
            }
            Candidate best = null;
            boolean tie = false;
            for (Candidate candidate : candidates.values()) {
                if (best == null || candidate.score > best.score) {
                    best = candidate;
                    tie = false;
                } else if (candidate.score == best.score && !candidate.method.equals(best.method)) {
                    tie = true;
                }
            }
            if (best != null && !tie) {
                best.method.setAccessible(true);
                return best.method;
            }
            if (tie) throw new NoSuchMethodException("DEX_LITERAL_ANCHOR_AMBIGUOUS " + literals);
            throw moved;
        }
    }

    private static final class Candidate {
        final Method method;
        int score;
        Candidate(Method method) { this.method = method; }
    }

    static List<String> classNames(String apk) throws IOException {
        return cachedClassNames(apk);
    }

    private static List<String> cachedClassNames(String apk) throws IOException {
        String key = fingerprint(apk);
        synchronized (CLASS_CACHE) {
            List<String> cached = CLASS_CACHE.get(key);
            if (cached != null) return cached;
        }
        List<String> parsed = List.copyOf(DexAnchors.classNames(apk));
        cachePut(CLASS_CACHE, key, parsed);
        return parsed;
    }

    private static List<DexAnchors.MethodRef> cachedMethods(String apk, String literal)
            throws IOException {
        String key = fingerprint(apk) + "\n" + literal;
        synchronized (ANCHOR_CACHE) {
            List<DexAnchors.MethodRef> cached = ANCHOR_CACHE.get(key);
            if (cached != null) return cached;
        }
        List<DexAnchors.MethodRef> parsed = List.copyOf(DexAnchors.methodsReferencing(apk, literal));
        cachePut(ANCHOR_CACHE, key, parsed);
        return parsed;
    }

    private static String fingerprint(String apk) {
        File file = new File(apk);
        return apk + "\n" + file.length() + "\n" + file.lastModified();
    }

    private static <T> void cachePut(LinkedHashMap<String, T> cache, String key, T value) {
        synchronized (cache) {
            cache.put(key, value);
            while (cache.size() > CACHE_LIMIT) {
                String eldest = cache.keySet().iterator().next();
                cache.remove(eldest);
            }
        }
    }

    private static boolean hasMethods(Class<?> type, String[] names) {
        if (names == null || names.length == 0) return true;
        for (String name : names) {
            if (name == null || name.isBlank()) continue;
            boolean found = false;
            for (Class<?> cursor = type; cursor != null && !found; cursor = cursor.getSuperclass()) {
                for (Method method : cursor.getDeclaredMethods()) {
                    if (name.equals(method.getName())) {
                        found = true;
                        break;
                    }
                }
            }
            if (!found) return false;
        }
        return true;
    }

    private static boolean hasFields(Class<?> type, String[] names) {
        if (names == null || names.length == 0) return true;
        for (String name : names) {
            if (name == null || name.isBlank()) continue;
            boolean found = false;
            for (Class<?> cursor = type; cursor != null; cursor = cursor.getSuperclass()) {
                try {
                    cursor.getDeclaredField(name);
                    found = true;
                    break;
                } catch (NoSuchFieldException ignored) { }
            }
            if (!found) return false;
        }
        return true;
    }

    private static boolean declaresSignatures(Class<?> type, Class<?>[][] signatures) {
        for (Class<?>[] signature : signatures) {
            boolean matched = false;
            for (Method method : type.getDeclaredMethods()) {
                if (sameParameters(method.getParameterTypes(), signature)) {
                    matched = true;
                    break;
                }
            }
            if (!matched) return false;
        }
        return true;
    }

    private static boolean sameParameters(Class<?>[] actual, Class<?>[] expected) {
        if (actual.length != expected.length) return false;
        for (int i = 0; i < actual.length; i++) {
            if (expected[i] != null && actual[i] != expected[i]) return false;
        }
        return true;
    }

    private static List<String> apkPaths(Context context) {
        if (context == null || context.getApplicationInfo() == null) return List.of();
        ArrayList<String> paths = new ArrayList<>();
        String source = context.getApplicationInfo().sourceDir;
        if (source != null && !source.isBlank()) paths.add(source);
        String[] splits = context.getApplicationInfo().splitSourceDirs;
        if (splits != null) {
            for (String split : splits) {
                if (split != null && !split.isBlank()) paths.add(split);
            }
        }
        return paths;
    }

    private static Class<?>[] descriptorClasses(String[] descriptors, ClassLoader loader)
            throws ClassNotFoundException {
        Class<?>[] result = new Class<?>[descriptors.length];
        for (int i = 0; i < descriptors.length; i++) {
            result[i] = descriptorClass(descriptors[i], loader);
        }
        return result;
    }

    private static Class<?> descriptorClass(String descriptor, ClassLoader loader)
            throws ClassNotFoundException {
        return switch (descriptor) {
            case "V" -> void.class;
            case "Z" -> boolean.class;
            case "B" -> byte.class;
            case "S" -> short.class;
            case "C" -> char.class;
            case "I" -> int.class;
            case "J" -> long.class;
            case "F" -> float.class;
            case "D" -> double.class;
            default -> Class.forName(binaryName(descriptor), false, loader);
        };
    }

    private static String binaryName(String descriptor) {
        if (descriptor == null || descriptor.isBlank()) return "";
        if (descriptor.charAt(0) == '[') return descriptor.replace('/', '.');
        if (descriptor.charAt(0) == 'L' && descriptor.endsWith(";")) {
            return descriptor.substring(1, descriptor.length() - 1).replace('/', '.');
        }
        return descriptor.replace('/', '.');
    }
}
