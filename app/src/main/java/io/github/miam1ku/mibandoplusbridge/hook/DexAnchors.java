// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.hook;

import android.content.Context;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Small host-dex resolver.
 *
 * Stable names are always the fast path. When a ColorOS/OHealth update moves or
 * obfuscates a class, resolution falls back to structural signatures or literals
 * referenced by method bodies. API 102's framework parser is preferred inside an
 * LSPosed process; the bounded pure-Java parser remains the fallback for tests and
 * runtimes where framework parsing is unavailable.
 */
final class DexAnchors {
    record MethodRef(String classDescriptor, String name, String[] parameters) {}

    private static final int CACHE_LIMIT = 24;
    private static final Map<String, List<String>> CLASS_CACHE =
            new LinkedHashMap<>(16, 0.75f, true);
    private static final Map<String, List<MethodRef>> ANCHOR_CACHE =
            new LinkedHashMap<>(16, 0.75f, true);

    private DexAnchors() {}

    static List<MethodRef> methodsReferencing(String apkPath, String literal) throws IOException {
        String key = cacheKey(apkPath) + "\n" + literal;
        synchronized (ANCHOR_CACHE) {
            List<MethodRef> cached = ANCHOR_CACHE.get(key);
            if (cached != null) return cached;
        }
        ArrayList<MethodRef> found = new ArrayList<>();
        byte[] needle = literal.getBytes(StandardCharsets.UTF_8);
        try (ZipFile zip = new ZipFile(apkPath)) {
            for (ZipEntry entry : java.util.Collections.list(zip.entries())) {
                if (!dexEntry(entry)) continue;
                byte[] dex = read(zip, entry);
                if (!frameworkMethods(dex, literal, found)) scan(dex, needle, found);
            }
        }
        List<MethodRef> immutable = List.copyOf(dedupe(found));
        cachePut(ANCHOR_CACHE, key, immutable);
        return immutable;
    }

    /**
     * Defined class names only. Never uses dalvik.system.DexFile, because some
     * Zygisk linker modes replace its dlopen path and can abort the host process.
     */
    static List<String> classNames(String apkPath) throws IOException {
        String key = cacheKey(apkPath);
        synchronized (CLASS_CACHE) {
            List<String> cached = CLASS_CACHE.get(key);
            if (cached != null) return cached;
        }
        ArrayList<String> found = new ArrayList<>();
        try (ZipFile zip = new ZipFile(apkPath)) {
            for (ZipEntry entry : java.util.Collections.list(zip.entries())) {
                if (!dexEntry(entry)) continue;
                byte[] dex = read(zip, entry);
                if (!frameworkClasses(dex, found)) collectClasses(dex, found);
            }
        }
        List<String> immutable = List.copyOf(new java.util.LinkedHashSet<>(found));
        cachePut(CLASS_CACHE, key, immutable);
        return immutable;
    }

    /**
     * Prefer the stable class, then locate the unique class in the host dex that
     * declares a method with the supplied parameter signature.
     */
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
                    for (String name : classNames(apk)) {
                        if (packagePrefix != null && !name.startsWith(packagePrefix)) continue;
                        if (name.indexOf('
    /** Stable method name first; unique signature fallback when a vendor renames it. */
    static Method resolveMethod(Class<?> owner, String stableName, Class<?> returnType,
            Class<?>... parameters) throws NoSuchMethodException {
        for (Class<?> cursor = owner; cursor != null; cursor = cursor.getSuperclass()) {
            try {
                Method named = cursor.getDeclaredMethod(stableName, parameters);
                if (returnType == null || named.getReturnType() == returnType) {
                    named.setAccessible(true);
                    return named;
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

    /**
     * Multi-anchor resolution. Each independent literal adds one score. Highest
     * unique score wins; a tie fails closed instead of guessing a hook target.
     */
    static Method resolveAnchoredMethod(Context context, ClassLoader loader,
            String stableClass, String stableMethod, List<String> literals,
            Class<?> ownerSuper, Class<?> returnType, Class<?>... parameters) throws Exception {
        try {
            Class<?> owner = Class.forName(stableClass, false, loader);
            return resolveMethod(owner, stableMethod, returnType, parameters);
        } catch (Throwable moved) {
            LinkedHashMap<String, Candidate> candidates = new LinkedHashMap<>();
            for (String literal : literals) {
                if (literal == null || literal.isBlank()) continue;
                HashSet<String> scoredThisAnchor = new HashSet<>();
                for (String apk : apkPaths(context)) {
                    for (MethodRef ref : methodsReferencing(apk, literal)) {
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
                        if (scoredThisAnchor.add(id)) candidate.score++;
                    }
                }
            }
            Candidate best = null;
            boolean tie = false;
            for (Candidate candidate : candidates.values()) {
                if (best == null || candidate.score > best.score) {
                    best = candidate;
                    tie = false;
                } else if (candidate.score == best.score
                        && !candidate.method.equals(best.method)) {
                    tie = true;
                }
            }
            if (best != null && !tie) {
                best.method.setAccessible(true);
                return best.method;
            }
            if (tie) throw new NoSuchMethodException("DEX_LITERAL_ANCHOR_AMBIGUOUS " + literals);
            if (moved instanceof Exception exception) throw exception;
            throw new NoSuchMethodException(stableClass + "#" + stableMethod);
        }
    }

    private static final class Candidate {
        final Method method;
        int score;
        Candidate(Method method) { this.method = method; }
    }

    private static boolean frameworkMethods(byte[] dex, String literal, List<MethodRef> found) {
        try {
            return FrameworkDex.methods(dex, literal, found);
        } catch (Throwable unavailable) {
            return false;
        }
    }

    private static boolean frameworkClasses(byte[] dex, List<String> found) {
        try {
            return FrameworkDex.classes(dex, found);
        } catch (Throwable unavailable) {
            return false;
        }
    }

    /**
     * Kept isolated so JVM unit tests can run even when the compileOnly libxposed
     * classes are not present on their runtime classpath.
     */
    private static final class FrameworkDex {
        static boolean methods(byte[] dex, String literal, List<MethodRef> found) throws Exception {
            io.github.libxposed.api.utils.DexParser parser = EntryPoint.openDexParser(dex, false);
            if (parser == null) return false;
            try (parser) {
                Set<Integer> strings = new HashSet<>();
                for (var id : parser.getStringId()) {
                    String text = id.getString();
                    if (text.equals(literal) || (text.startsWith(literal)
                            && text.length() > literal.length()
                            && text.charAt(literal.length()) == ' ')) {
                        strings.add(id.getId());
                    }
                }
                if (strings.isEmpty()) return true;
                var methods = parser.getMethodId();
                Set<Integer> added = new HashSet<>();
                parser.visitDefinedClasses(new io.github.libxposed.api.utils.DexParser.ClassVisitor() {
                    @Override public io.github.libxposed.api.utils.DexParser.MemberVisitor visit(
                            int clazz, int accessFlags, int superClass, int[] interfaces, int sourceFile,
                            int[] staticFields, int[] staticFieldsAccessFlags,
                            int[] instanceFields, int[] instanceFieldsAccessFlags,
                            int[] directMethods, int[] directMethodsAccessFlags,
                            int[] virtualMethods, int[] virtualMethodsAccessFlags, int[] annotations) {
                        return new io.github.libxposed.api.utils.DexParser.MethodVisitor() {
                            @Override public io.github.libxposed.api.utils.DexParser.MethodBodyVisitor visit(
                                    int method, int flags, boolean hasBody, int[] methodAnnotations,
                                    int[] parameterAnnotations) {
                                if (!hasBody) return null;
                                return (methodIndex, bodyFlags, referredStrings, invokedMethods,
                                        accessedFields, assignedFields, opcodes) -> {
                                    if (!containsAny(referredStrings, strings) || !added.add(methodIndex)) return;
                                    if (methodIndex < 0 || methodIndex >= methods.length) return;
                                    found.add(methodRef(methods[methodIndex]));
                                };
                            }
                            @Override public boolean stop() { return false; }
                        };
                    }
                    @Override public boolean stop() { return false; }
                });
                return true;
            }
        }

        static boolean classes(byte[] dex, List<String> found) throws Exception {
            io.github.libxposed.api.utils.DexParser parser = EntryPoint.openDexParser(dex, false);
            if (parser == null) return false;
            try (parser) {
                var types = parser.getTypeId();
                parser.visitDefinedClasses(new io.github.libxposed.api.utils.DexParser.ClassVisitor() {
                    @Override public io.github.libxposed.api.utils.DexParser.MemberVisitor visit(
                            int clazz, int accessFlags, int superClass, int[] interfaces, int sourceFile,
                            int[] staticFields, int[] staticFieldsAccessFlags,
                            int[] instanceFields, int[] instanceFieldsAccessFlags,
                            int[] directMethods, int[] directMethodsAccessFlags,
                            int[] virtualMethods, int[] virtualMethodsAccessFlags, int[] annotations) {
                        if (clazz >= 0 && clazz < types.length) {
                            String descriptor = types[clazz].getDescriptor().getString();
                            String name = className(descriptor);
                            if (!name.isBlank()) found.add(name);
                        }
                        return null;
                    }
                    @Override public boolean stop() { return false; }
                });
                return true;
            }
        }

        private static MethodRef methodRef(io.github.libxposed.api.utils.DexParser.MethodId method) {
            String owner = method.getDeclaringClass().getDescriptor().getString();
            String name = method.getName().getString();
            var params = method.getPrototype().getParameters();
            String[] descriptors = params == null ? new String[0] : new String[params.length];
            if (params != null) {
                for (int i = 0; i < params.length; i++) {
                    descriptors[i] = params[i].getDescriptor().getString();
                }
            }
            return new MethodRef(owner, name, descriptors);
        }

        private static boolean containsAny(int[] values, Set<Integer> wanted) {
            for (int value : values) if (wanted.contains(value)) return true;
            return false;
        }
    }

    private static ArrayList<MethodRef> dedupe(List<MethodRef> refs) {
        LinkedHashMap<String, MethodRef> unique = new LinkedHashMap<>();
        for (MethodRef ref : refs) {
            String key = ref.classDescriptor() + "#" + ref.name()
                    + Arrays.toString(ref.parameters());
            unique.putIfAbsent(key, ref);
        }
        return new ArrayList<>(unique.values());
    }

    private static boolean dexEntry(ZipEntry entry) {
        String name = entry.getName();
        return name.startsWith("classes") && name.endsWith(".dex") && name.indexOf('/') < 0;
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
        ArrayList<String> apks = new ArrayList<>();
        String source = context.getApplicationInfo().sourceDir;
        if (source != null && !source.isBlank()) apks.add(source);
        String[] splits = context.getApplicationInfo().splitSourceDirs;
        if (splits != null) {
            for (String split : splits) {
                if (split != null && !split.isBlank()) apks.add(split);
            }
        }
        return apks;
    }

    private static Class<?>[] descriptorClasses(String[] descriptors, ClassLoader loader)
            throws ClassNotFoundException {
        Class<?>[] types = new Class<?>[descriptors.length];
        for (int i = 0; i < descriptors.length; i++) {
            types[i] = descriptorClass(descriptors[i], loader);
        }
        return types;
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

    private static String className(String descriptor) {
        if (descriptor == null || descriptor.length() < 2
                || descriptor.charAt(0) != 'L' || !descriptor.endsWith(";")) return "";
        return descriptor.substring(1, descriptor.length() - 1).replace('/', '.');
    }

    private static String cacheKey(String apkPath) {
        File file = new File(apkPath);
        return apkPath + "\n" + file.length() + "\n" + file.lastModified();
    }

    private static <T> void cachePut(Map<String, T> cache, String key, T value) {
        synchronized (cache) {
            cache.put(key, value);
            while (cache.size() > CACHE_LIMIT) {
                String eldest = cache.keySet().iterator().next();
                cache.remove(eldest);
            }
        }
    }

    private static void collectClasses(byte[] dex, List<String> found) {
        if (dex.length < 112 || dex[0] != 'd' || dex[1] != 'e'
                || dex[2] != 'x' || dex[3] != '\n') return;
        ByteBuffer buf = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN);
        int stringIdsSize = buf.getInt(56);
        int stringIdsOff = buf.getInt(60);
        int typeIdsSize = buf.getInt(64);
        int typeIdsOff = buf.getInt(68);
        int classDefsSize = buf.getInt(96);
        int classDefsOff = buf.getInt(100);
        if (stringIdsSize <= 0 || typeIdsSize <= 0 || classDefsSize <= 0) return;
        if (stringIdsSize > 1_000_000 || typeIdsSize > 1_000_000 || classDefsSize > 1_000_000) return;
        for (int ci = 0; ci < classDefsSize; ci++) {
            int def = classDefsOff + ci * 32;
            if (def < 0 || def + 4 > dex.length) return;
            int classIdx = buf.getInt(def);
            if (classIdx < 0 || classIdx >= typeIdsSize) continue;
            int type = typeIdsOff + classIdx * 4;
            if (type < 0 || type + 4 > dex.length) continue;
            int stringIdx = buf.getInt(type);
            if (stringIdx < 0 || stringIdx >= stringIdsSize) continue;
            int id = stringIdsOff + stringIdx * 4;
            if (id < 0 || id + 4 > dex.length) continue;
            String descriptor = safeText(dex, buf.getInt(id));
            String name = className(descriptor);
            if (!name.isBlank()) found.add(name);
        }
    }

    private static String safeText(byte[] dex, int off) {
        if (off < 0 || off >= dex.length) return "";
        int pos = off;
        int shift = 0;
        while (pos < dex.length && shift <= 28) {
            int b = dex[pos++] & 0xff;
            if (b < 0x80) break;
            shift += 7;
        }
        int end = pos;
        while (end < dex.length && dex[end] != 0) end++;
        if (end >= dex.length) return "";
        return new String(dex, pos, end - pos, StandardCharsets.UTF_8);
    }

    private static byte[] read(ZipFile zip, ZipEntry entry) throws IOException {
        try (InputStream in = zip.getInputStream(entry)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            in.transferTo(out);
            return out.toByteArray();
        }
    }

    private static void scan(byte[] dex, byte[] needle, List<MethodRef> found) {
        if (dex.length < 112 || dex[0] != 'd' || dex[1] != 'e' || dex[2] != 'x') return;
        ByteBuffer buf = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN);
        int stringIdsSize = buf.getInt(56);
        int stringIdsOff = buf.getInt(60);
        int typeIdsSize = buf.getInt(64);
        int typeIdsOff = buf.getInt(68);
        int protoIdsSize = buf.getInt(72);
        int protoIdsOff = buf.getInt(76);
        int methodIdsSize = buf.getInt(88);
        int methodIdsOff = buf.getInt(92);
        int classDefsSize = buf.getInt(96);
        int classDefsOff = buf.getInt(100);
        int literal = -1;
        for (int i = 0; i < stringIdsSize; i++) {
            int at = stringIdsOff + i * 4;
            if (at < 0 || at + 4 > dex.length) return;
            if (anchor(stringBytes(dex, buf.getInt(at)), needle)) {
                literal = i;
                break;
            }
        }
        if (literal < 0) return;
        byte[] width = widths();
        for (int ci = 0; ci < classDefsSize; ci++) {
            int classDef = classDefsOff + ci * 32;
            if (classDef < 0 || classDef + 28 > dex.length) return;
            int classData = buf.getInt(classDef + 24);
            if (classData == 0) continue;
            try {
                Cursor cursor = new Cursor(dex, classData);
                int[] sizes = new int[4];
                for (int i = 0; i < 4; i++) sizes[i] = cursor.uleb();
                for (int i = 0; i < sizes[0] + sizes[1]; i++) {
                    cursor.uleb();
                    cursor.uleb();
                }
                for (int list = 0; list < 2; list++) {
                    int methodIdx = 0;
                    for (int i = 0; i < sizes[2 + list]; i++) {
                        methodIdx += cursor.uleb();
                        cursor.uleb();
                        int code = cursor.uleb();
                        if (methodIdx < 0 || methodIdx >= methodIdsSize) {
                            throw new IllegalStateException("idx");
                        }
                        if (code != 0 && references(dex, code, literal, width)) {
                            found.add(methodRef(dex, buf, methodIdx, methodIdsOff,
                                    typeIdsOff, typeIdsSize, protoIdsOff, protoIdsSize, stringIdsOff));
                        }
                    }
                }
            } catch (RuntimeException skipped) {
                // A damaged class_data item must not hide anchors in later classes.
            }
        }
    }

    private static boolean references(byte[] dex, int codeOff, int literal, byte[] width) {
        if (codeOff < 0 || codeOff + 16 > dex.length) return false;
        ByteBuffer buf = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN);
        int insnsSize = buf.getInt(codeOff + 12);
        int insnsOff = codeOff + 16;
        if (insnsSize <= 0 || insnsSize > 200_000
                || insnsOff + (long) insnsSize * 2 > dex.length) return false;
        for (int i = 0; i < insnsSize; ) {
            int unit = buf.getShort(insnsOff + i * 2) & 0xffff;
            int op = unit & 0xff;
            int size = width[op] & 0xff;
            if (size == 0 || i + size > insnsSize) return false;
            if (op == 0x1a
                    && (buf.getShort(insnsOff + (i + 1) * 2) & 0xffff) == literal) return true;
            if (op == 0x1b && i + 2 < insnsSize) {
                int sid = (buf.getShort(insnsOff + (i + 1) * 2) & 0xffff)
                        | ((buf.getShort(insnsOff + (i + 2) * 2) & 0xffff) << 16);
                if (sid == literal) return true;
            }
            i += size;
        }
        return false;
    }

    private static MethodRef methodRef(byte[] dex, ByteBuffer buf, int methodIdx, int methodIdsOff,
            int typeIdsOff, int typeIdsSize, int protoIdsOff, int protoIdsSize, int stringIdsOff) {
        int method = methodIdsOff + methodIdx * 8;
        if (method < 0 || method + 8 > dex.length) throw new IllegalStateException("ref");
        int classIdx = buf.getShort(method) & 0xffff;
        int protoIdx = buf.getShort(method + 2) & 0xffff;
        int nameIdx = buf.getInt(method + 4);
        if (classIdx >= typeIdsSize || protoIdx >= protoIdsSize) throw new IllegalStateException("ref");
        String className = cstring(dex,
                buf.getInt(stringIdsOff + (buf.getInt(typeIdsOff + classIdx * 4)) * 4));
        String name = cstring(dex, buf.getInt(stringIdsOff + nameIdx * 4));
        int proto = protoIdsOff + protoIdx * 12;
        int paramsOff = buf.getInt(proto + 8);
        String[] params = new String[0];
        if (paramsOff != 0) {
            int count = buf.getInt(paramsOff);
            if (count < 0 || count > 65535) throw new IllegalStateException("params");
            params = new String[count];
            for (int i = 0; i < count; i++) {
                int typeIdx = buf.getShort(paramsOff + 4 + i * 2) & 0xffff;
                params[i] = cstring(dex,
                        buf.getInt(stringIdsOff + (buf.getInt(typeIdsOff + typeIdx * 4)) * 4));
            }
        }
        return new MethodRef(className, name, params);
    }

    private static byte[] stringBytes(byte[] dex, int off) {
        int[] pos = new int[] {off};
        uleb(dex, pos);
        int end = pos[0];
        while (end < dex.length && dex[end] != 0) end++;
        if (pos[0] < 0 || pos[0] > end || end > dex.length) return new byte[0];
        return Arrays.copyOfRange(dex, pos[0], end);
    }

    private static String cstring(byte[] dex, int off) {
        int[] pos = new int[] {off};
        uleb(dex, pos);
        int end = pos[0];
        while (end < dex.length && dex[end] != 0) end++;
        if (pos[0] < 0 || pos[0] > end || end > dex.length) return "";
        return new String(dex, pos[0], end - pos[0], StandardCharsets.UTF_8);
    }

    private static boolean anchor(byte[] text, byte[] needle) {
        if (text.length < needle.length) return false;
        for (int i = 0; i < needle.length; i++) {
            if (text[i] != needle[i]) return false;
        }
        return text.length == needle.length || text[needle.length] == ' ';
    }

    private static int uleb(byte[] dex, int[] pos) {
        int value = 0;
        int shift = 0;
        while (pos[0] < dex.length && shift <= 28) {
            int b = dex[pos[0]++] & 0xff;
            value |= (b & 0x7f) << shift;
            if (b < 0x80) return value;
            shift += 7;
        }
        throw new IllegalStateException("uleb");
    }

    private static final class Cursor {
        private final byte[] dex;
        private int pos;
        Cursor(byte[] dex, int pos) { this.dex = dex; this.pos = pos; }
        int uleb() {
            int[] at = new int[] {pos};
            int value = DexAnchors.uleb(dex, at);
            pos = at[0];
            return value;
        }
    }

    /** Widths in 16-bit code units. */
    private static byte[] widths() {
        byte[] w = new byte[256];
        int[] one = {0x00, 0x01, 0x04, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                0x11, 0x12, 0x1d, 0x1e, 0x21, 0x27, 0x28};
        int[] two = {0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f, 0x20,
                0x22, 0x23, 0x29};
        int[] three = {0x03, 0x06, 0x09, 0x14, 0x17, 0x1b, 0x24, 0x25, 0x26, 0x2a, 0x2b,
                0x2c, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78};
        for (int op : one) w[op] = 1;
        for (int op = 0x7b; op <= 0x8f; op++) w[op] = 1;
        for (int op = 0xb0; op <= 0xcf; op++) w[op] = 1;
        for (int op : two) w[op] = 2;
        for (int op = 0x2d; op <= 0x3d; op++) w[op] = 2;
        for (int op = 0x44; op <= 0x6d; op++) w[op] = 2;
        for (int op = 0x90; op <= 0xe2; op++) w[op] = 2;
        for (int op : three) w[op] = 3;
        for (int op = 0xe3; op <= 0xff; op++) w[op] = 3;
        w[0x18] = 5;
        return w;
    }
}
) >= 0) continue;
                        Class<?> type;
                        try {
                            type = Class.forName(name, false, loader);
                        } catch (Throwable unavailable) {
                            continue;
                        }
                        if (!declaresSignatures(type, signatures)) continue;
                        if (found != null && found != type) {
                            throw new IllegalStateException("DEX_CLASS_SIGNATURE_AMBIGUOUS");
                        }
                        found = type;
                    }
                } catch (IOException ignored) { }
            }
            if (found != null) return found;
            throw missing;
        }
    }

    /** Stable method name first; unique signature fallback when a vendor renames it. */
    static Method resolveMethod(Class<?> owner, String stableName, Class<?> returnType,
            Class<?>... parameters) throws NoSuchMethodException {
        for (Class<?> cursor = owner; cursor != null; cursor = cursor.getSuperclass()) {
            try {
                Method named = cursor.getDeclaredMethod(stableName, parameters);
                if (returnType == null || named.getReturnType() == returnType) {
                    named.setAccessible(true);
                    return named;
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

    /**
     * Multi-anchor resolution. Each independent literal adds one score. Highest
     * unique score wins; a tie fails closed instead of guessing a hook target.
     */
    static Method resolveAnchoredMethod(Context context, ClassLoader loader,
            String stableClass, String stableMethod, List<String> literals,
            Class<?> ownerSuper, Class<?> returnType, Class<?>... parameters) throws Exception {
        try {
            Class<?> owner = Class.forName(stableClass, false, loader);
            return resolveMethod(owner, stableMethod, returnType, parameters);
        } catch (Throwable moved) {
            LinkedHashMap<String, Candidate> candidates = new LinkedHashMap<>();
            for (String literal : literals) {
                if (literal == null || literal.isBlank()) continue;
                HashSet<String> scoredThisAnchor = new HashSet<>();
                for (String apk : apkPaths(context)) {
                    for (MethodRef ref : methodsReferencing(apk, literal)) {
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
                        if (scoredThisAnchor.add(id)) candidate.score++;
                    }
                }
            }
            Candidate best = null;
            boolean tie = false;
            for (Candidate candidate : candidates.values()) {
                if (best == null || candidate.score > best.score) {
                    best = candidate;
                    tie = false;
                } else if (candidate.score == best.score
                        && !candidate.method.equals(best.method)) {
                    tie = true;
                }
            }
            if (best != null && !tie) {
                best.method.setAccessible(true);
                return best.method;
            }
            if (tie) throw new NoSuchMethodException("DEX_LITERAL_ANCHOR_AMBIGUOUS " + literals);
            if (moved instanceof Exception exception) throw exception;
            throw new NoSuchMethodException(stableClass + "#" + stableMethod);
        }
    }

    private static final class Candidate {
        final Method method;
        int score;
        Candidate(Method method) { this.method = method; }
    }

    private static boolean frameworkMethods(byte[] dex, String literal, List<MethodRef> found) {
        try {
            return FrameworkDex.methods(dex, literal, found);
        } catch (Throwable unavailable) {
            return false;
        }
    }

    private static boolean frameworkClasses(byte[] dex, List<String> found) {
        try {
            return FrameworkDex.classes(dex, found);
        } catch (Throwable unavailable) {
            return false;
        }
    }

    /**
     * Kept isolated so JVM unit tests can run even when the compileOnly libxposed
     * classes are not present on their runtime classpath.
     */
    private static final class FrameworkDex {
        static boolean methods(byte[] dex, String literal, List<MethodRef> found) throws Exception {
            io.github.libxposed.api.utils.DexParser parser = EntryPoint.openDexParser(dex, false);
            if (parser == null) return false;
            try (parser) {
                Set<Integer> strings = new HashSet<>();
                for (var id : parser.getStringId()) {
                    String text = id.getString();
                    if (text.equals(literal) || (text.startsWith(literal)
                            && text.length() > literal.length()
                            && text.charAt(literal.length()) == ' ')) {
                        strings.add(id.getId());
                    }
                }
                if (strings.isEmpty()) return true;
                var methods = parser.getMethodId();
                Set<Integer> added = new HashSet<>();
                parser.visitDefinedClasses(new io.github.libxposed.api.utils.DexParser.ClassVisitor() {
                    @Override public io.github.libxposed.api.utils.DexParser.MemberVisitor visit(
                            int clazz, int accessFlags, int superClass, int[] interfaces, int sourceFile,
                            int[] staticFields, int[] staticFieldsAccessFlags,
                            int[] instanceFields, int[] instanceFieldsAccessFlags,
                            int[] directMethods, int[] directMethodsAccessFlags,
                            int[] virtualMethods, int[] virtualMethodsAccessFlags, int[] annotations) {
                        return new io.github.libxposed.api.utils.DexParser.MethodVisitor() {
                            @Override public io.github.libxposed.api.utils.DexParser.MethodBodyVisitor visit(
                                    int method, int flags, boolean hasBody, int[] methodAnnotations,
                                    int[] parameterAnnotations) {
                                if (!hasBody) return null;
                                return (methodIndex, bodyFlags, referredStrings, invokedMethods,
                                        accessedFields, assignedFields, opcodes) -> {
                                    if (!containsAny(referredStrings, strings) || !added.add(methodIndex)) return;
                                    if (methodIndex < 0 || methodIndex >= methods.length) return;
                                    found.add(methodRef(methods[methodIndex]));
                                };
                            }
                            @Override public boolean stop() { return false; }
                        };
                    }
                    @Override public boolean stop() { return false; }
                });
                return true;
            }
        }

        static boolean classes(byte[] dex, List<String> found) throws Exception {
            io.github.libxposed.api.utils.DexParser parser = EntryPoint.openDexParser(dex, false);
            if (parser == null) return false;
            try (parser) {
                var types = parser.getTypeId();
                parser.visitDefinedClasses(new io.github.libxposed.api.utils.DexParser.ClassVisitor() {
                    @Override public io.github.libxposed.api.utils.DexParser.MemberVisitor visit(
                            int clazz, int accessFlags, int superClass, int[] interfaces, int sourceFile,
                            int[] staticFields, int[] staticFieldsAccessFlags,
                            int[] instanceFields, int[] instanceFieldsAccessFlags,
                            int[] directMethods, int[] directMethodsAccessFlags,
                            int[] virtualMethods, int[] virtualMethodsAccessFlags, int[] annotations) {
                        if (clazz >= 0 && clazz < types.length) {
                            String descriptor = types[clazz].getDescriptor().getString();
                            String name = className(descriptor);
                            if (!name.isBlank()) found.add(name);
                        }
                        return null;
                    }
                    @Override public boolean stop() { return false; }
                });
                return true;
            }
        }

        private static MethodRef methodRef(io.github.libxposed.api.utils.DexParser.MethodId method) {
            String owner = method.getDeclaringClass().getDescriptor().getString();
            String name = method.getName().getString();
            var params = method.getPrototype().getParameters();
            String[] descriptors = params == null ? new String[0] : new String[params.length];
            if (params != null) {
                for (int i = 0; i < params.length; i++) {
                    descriptors[i] = params[i].getDescriptor().getString();
                }
            }
            return new MethodRef(owner, name, descriptors);
        }

        private static boolean containsAny(int[] values, Set<Integer> wanted) {
            for (int value : values) if (wanted.contains(value)) return true;
            return false;
        }
    }

    private static ArrayList<MethodRef> dedupe(List<MethodRef> refs) {
        LinkedHashMap<String, MethodRef> unique = new LinkedHashMap<>();
        for (MethodRef ref : refs) {
            String key = ref.classDescriptor() + "#" + ref.name()
                    + Arrays.toString(ref.parameters());
            unique.putIfAbsent(key, ref);
        }
        return new ArrayList<>(unique.values());
    }

    private static boolean dexEntry(ZipEntry entry) {
        String name = entry.getName();
        return name.startsWith("classes") && name.endsWith(".dex") && name.indexOf('/') < 0;
    }

    private static boolean declaresSignature(Class<?> type, Class<?>[] parameters) {
        for (Method method : type.getDeclaredMethods()) {
            if (sameParameters(method.getParameterTypes(), parameters)) return true;
        }
        return false;
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
        ArrayList<String> apks = new ArrayList<>();
        String source = context.getApplicationInfo().sourceDir;
        if (source != null && !source.isBlank()) apks.add(source);
        String[] splits = context.getApplicationInfo().splitSourceDirs;
        if (splits != null) {
            for (String split : splits) {
                if (split != null && !split.isBlank()) apks.add(split);
            }
        }
        return apks;
    }

    private static Class<?>[] descriptorClasses(String[] descriptors, ClassLoader loader)
            throws ClassNotFoundException {
        Class<?>[] types = new Class<?>[descriptors.length];
        for (int i = 0; i < descriptors.length; i++) {
            types[i] = descriptorClass(descriptors[i], loader);
        }
        return types;
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

    private static String className(String descriptor) {
        if (descriptor == null || descriptor.length() < 2
                || descriptor.charAt(0) != 'L' || !descriptor.endsWith(";")) return "";
        return descriptor.substring(1, descriptor.length() - 1).replace('/', '.');
    }

    private static String cacheKey(String apkPath) {
        File file = new File(apkPath);
        return apkPath + "\n" + file.length() + "\n" + file.lastModified();
    }

    private static <T> void cachePut(Map<String, T> cache, String key, T value) {
        synchronized (cache) {
            cache.put(key, value);
            while (cache.size() > CACHE_LIMIT) {
                String eldest = cache.keySet().iterator().next();
                cache.remove(eldest);
            }
        }
    }

    private static void collectClasses(byte[] dex, List<String> found) {
        if (dex.length < 112 || dex[0] != 'd' || dex[1] != 'e'
                || dex[2] != 'x' || dex[3] != '\n') return;
        ByteBuffer buf = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN);
        int stringIdsSize = buf.getInt(56);
        int stringIdsOff = buf.getInt(60);
        int typeIdsSize = buf.getInt(64);
        int typeIdsOff = buf.getInt(68);
        int classDefsSize = buf.getInt(96);
        int classDefsOff = buf.getInt(100);
        if (stringIdsSize <= 0 || typeIdsSize <= 0 || classDefsSize <= 0) return;
        if (stringIdsSize > 1_000_000 || typeIdsSize > 1_000_000 || classDefsSize > 1_000_000) return;
        for (int ci = 0; ci < classDefsSize; ci++) {
            int def = classDefsOff + ci * 32;
            if (def < 0 || def + 4 > dex.length) return;
            int classIdx = buf.getInt(def);
            if (classIdx < 0 || classIdx >= typeIdsSize) continue;
            int type = typeIdsOff + classIdx * 4;
            if (type < 0 || type + 4 > dex.length) continue;
            int stringIdx = buf.getInt(type);
            if (stringIdx < 0 || stringIdx >= stringIdsSize) continue;
            int id = stringIdsOff + stringIdx * 4;
            if (id < 0 || id + 4 > dex.length) continue;
            String descriptor = safeText(dex, buf.getInt(id));
            String name = className(descriptor);
            if (!name.isBlank()) found.add(name);
        }
    }

    private static String safeText(byte[] dex, int off) {
        if (off < 0 || off >= dex.length) return "";
        int pos = off;
        int shift = 0;
        while (pos < dex.length && shift <= 28) {
            int b = dex[pos++] & 0xff;
            if (b < 0x80) break;
            shift += 7;
        }
        int end = pos;
        while (end < dex.length && dex[end] != 0) end++;
        if (end >= dex.length) return "";
        return new String(dex, pos, end - pos, StandardCharsets.UTF_8);
    }

    private static byte[] read(ZipFile zip, ZipEntry entry) throws IOException {
        try (InputStream in = zip.getInputStream(entry)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            in.transferTo(out);
            return out.toByteArray();
        }
    }

    private static void scan(byte[] dex, byte[] needle, List<MethodRef> found) {
        if (dex.length < 112 || dex[0] != 'd' || dex[1] != 'e' || dex[2] != 'x') return;
        ByteBuffer buf = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN);
        int stringIdsSize = buf.getInt(56);
        int stringIdsOff = buf.getInt(60);
        int typeIdsSize = buf.getInt(64);
        int typeIdsOff = buf.getInt(68);
        int protoIdsSize = buf.getInt(72);
        int protoIdsOff = buf.getInt(76);
        int methodIdsSize = buf.getInt(88);
        int methodIdsOff = buf.getInt(92);
        int classDefsSize = buf.getInt(96);
        int classDefsOff = buf.getInt(100);
        int literal = -1;
        for (int i = 0; i < stringIdsSize; i++) {
            int at = stringIdsOff + i * 4;
            if (at < 0 || at + 4 > dex.length) return;
            if (anchor(stringBytes(dex, buf.getInt(at)), needle)) {
                literal = i;
                break;
            }
        }
        if (literal < 0) return;
        byte[] width = widths();
        for (int ci = 0; ci < classDefsSize; ci++) {
            int classDef = classDefsOff + ci * 32;
            if (classDef < 0 || classDef + 28 > dex.length) return;
            int classData = buf.getInt(classDef + 24);
            if (classData == 0) continue;
            try {
                Cursor cursor = new Cursor(dex, classData);
                int[] sizes = new int[4];
                for (int i = 0; i < 4; i++) sizes[i] = cursor.uleb();
                for (int i = 0; i < sizes[0] + sizes[1]; i++) {
                    cursor.uleb();
                    cursor.uleb();
                }
                for (int list = 0; list < 2; list++) {
                    int methodIdx = 0;
                    for (int i = 0; i < sizes[2 + list]; i++) {
                        methodIdx += cursor.uleb();
                        cursor.uleb();
                        int code = cursor.uleb();
                        if (methodIdx < 0 || methodIdx >= methodIdsSize) {
                            throw new IllegalStateException("idx");
                        }
                        if (code != 0 && references(dex, code, literal, width)) {
                            found.add(methodRef(dex, buf, methodIdx, methodIdsOff,
                                    typeIdsOff, typeIdsSize, protoIdsOff, protoIdsSize, stringIdsOff));
                        }
                    }
                }
            } catch (RuntimeException skipped) {
                // A damaged class_data item must not hide anchors in later classes.
            }
        }
    }

    private static boolean references(byte[] dex, int codeOff, int literal, byte[] width) {
        if (codeOff < 0 || codeOff + 16 > dex.length) return false;
        ByteBuffer buf = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN);
        int insnsSize = buf.getInt(codeOff + 12);
        int insnsOff = codeOff + 16;
        if (insnsSize <= 0 || insnsSize > 200_000
                || insnsOff + (long) insnsSize * 2 > dex.length) return false;
        for (int i = 0; i < insnsSize; ) {
            int unit = buf.getShort(insnsOff + i * 2) & 0xffff;
            int op = unit & 0xff;
            int size = width[op] & 0xff;
            if (size == 0 || i + size > insnsSize) return false;
            if (op == 0x1a
                    && (buf.getShort(insnsOff + (i + 1) * 2) & 0xffff) == literal) return true;
            if (op == 0x1b && i + 2 < insnsSize) {
                int sid = (buf.getShort(insnsOff + (i + 1) * 2) & 0xffff)
                        | ((buf.getShort(insnsOff + (i + 2) * 2) & 0xffff) << 16);
                if (sid == literal) return true;
            }
            i += size;
        }
        return false;
    }

    private static MethodRef methodRef(byte[] dex, ByteBuffer buf, int methodIdx, int methodIdsOff,
            int typeIdsOff, int typeIdsSize, int protoIdsOff, int protoIdsSize, int stringIdsOff) {
        int method = methodIdsOff + methodIdx * 8;
        if (method < 0 || method + 8 > dex.length) throw new IllegalStateException("ref");
        int classIdx = buf.getShort(method) & 0xffff;
        int protoIdx = buf.getShort(method + 2) & 0xffff;
        int nameIdx = buf.getInt(method + 4);
        if (classIdx >= typeIdsSize || protoIdx >= protoIdsSize) throw new IllegalStateException("ref");
        String className = cstring(dex,
                buf.getInt(stringIdsOff + (buf.getInt(typeIdsOff + classIdx * 4)) * 4));
        String name = cstring(dex, buf.getInt(stringIdsOff + nameIdx * 4));
        int proto = protoIdsOff + protoIdx * 12;
        int paramsOff = buf.getInt(proto + 8);
        String[] params = new String[0];
        if (paramsOff != 0) {
            int count = buf.getInt(paramsOff);
            if (count < 0 || count > 65535) throw new IllegalStateException("params");
            params = new String[count];
            for (int i = 0; i < count; i++) {
                int typeIdx = buf.getShort(paramsOff + 4 + i * 2) & 0xffff;
                params[i] = cstring(dex,
                        buf.getInt(stringIdsOff + (buf.getInt(typeIdsOff + typeIdx * 4)) * 4));
            }
        }
        return new MethodRef(className, name, params);
    }

    private static byte[] stringBytes(byte[] dex, int off) {
        int[] pos = new int[] {off};
        uleb(dex, pos);
        int end = pos[0];
        while (end < dex.length && dex[end] != 0) end++;
        if (pos[0] < 0 || pos[0] > end || end > dex.length) return new byte[0];
        return Arrays.copyOfRange(dex, pos[0], end);
    }

    private static String cstring(byte[] dex, int off) {
        int[] pos = new int[] {off};
        uleb(dex, pos);
        int end = pos[0];
        while (end < dex.length && dex[end] != 0) end++;
        if (pos[0] < 0 || pos[0] > end || end > dex.length) return "";
        return new String(dex, pos[0], end - pos[0], StandardCharsets.UTF_8);
    }

    private static boolean anchor(byte[] text, byte[] needle) {
        if (text.length < needle.length) return false;
        for (int i = 0; i < needle.length; i++) {
            if (text[i] != needle[i]) return false;
        }
        return text.length == needle.length || text[needle.length] == ' ';
    }

    private static int uleb(byte[] dex, int[] pos) {
        int value = 0;
        int shift = 0;
        while (pos[0] < dex.length && shift <= 28) {
            int b = dex[pos[0]++] & 0xff;
            value |= (b & 0x7f) << shift;
            if (b < 0x80) return value;
            shift += 7;
        }
        throw new IllegalStateException("uleb");
    }

    private static final class Cursor {
        private final byte[] dex;
        private int pos;
        Cursor(byte[] dex, int pos) { this.dex = dex; this.pos = pos; }
        int uleb() {
            int[] at = new int[] {pos};
            int value = DexAnchors.uleb(dex, at);
            pos = at[0];
            return value;
        }
    }

    /** Widths in 16-bit code units. */
    private static byte[] widths() {
        byte[] w = new byte[256];
        int[] one = {0x00, 0x01, 0x04, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                0x11, 0x12, 0x1d, 0x1e, 0x21, 0x27, 0x28};
        int[] two = {0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f, 0x20,
                0x22, 0x23, 0x29};
        int[] three = {0x03, 0x06, 0x09, 0x14, 0x17, 0x1b, 0x24, 0x25, 0x26, 0x2a, 0x2b,
                0x2c, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78};
        for (int op : one) w[op] = 1;
        for (int op = 0x7b; op <= 0x8f; op++) w[op] = 1;
        for (int op = 0xb0; op <= 0xcf; op++) w[op] = 1;
        for (int op : two) w[op] = 2;
        for (int op = 0x2d; op <= 0x3d; op++) w[op] = 2;
        for (int op = 0x44; op <= 0x6d; op++) w[op] = 2;
        for (int op = 0x90; op <= 0xe2; op++) w[op] = 2;
        for (int op : three) w[op] = 3;
        for (int op = 0xe3; op <= 0xff; op++) w[op] = 3;
        w[0x18] = 5;
        return w;
    }
}
