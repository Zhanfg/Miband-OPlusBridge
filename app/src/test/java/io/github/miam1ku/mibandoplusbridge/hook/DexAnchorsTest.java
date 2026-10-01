// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.hook;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.lang.reflect.Method;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.Test;
import static org.junit.Assert.*;

public final class DexAnchorsTest {
    @Test public void classNamesComeFromDexBytesNotTheLinker() throws Exception {
        Path apk = Files.createTempFile("dex-anchors", ".apk");
        try {
            try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(apk))) {
                byte[] compact = dex("Lcdex/ShouldSkip;");
                compact[0] = 'c';
                put(zip, "classes.dex", compact);
                put(zip, "classes2.dex", dex(
                        "Laa/Nw;",
                        "Laa/Nw$a;",
                        "Lcom/heytap/health/device/tab/itemview/wearable/MenuSleepItem;"));
                put(zip, "assets/classes.dex", dex("Lignored/NotADexEntry;"));
            }
            List<String> names = DexAnchors.classNames(apk.toString());
            assertEquals(List.of(
                    "aa.Nw",
                    "aa.Nw$a",
                    "com.heytap.health.device.tab.itemview.wearable.MenuSleepItem"), names);
            assertFalse(names.contains("cdex.ShouldSkip"));
            assertFalse(names.contains("ignored.NotADexEntry"));
        } finally {
            Files.deleteIfExists(apk);
        }
    }

    @Test public void literalAnchorFindsMethodInPureJavaFallback() throws Exception {
        Path apk = Files.createTempFile("dex-anchor-method", ".apk");
        try {
            try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(apk))) {
                put(zip, "classes.dex", dexWithAnchoredMethod("settingsDeviceMacBundle"));
            }
            List<DexAnchors.MethodRef> refs =
                    DexAnchors.methodsReferencing(apk.toString(), "settingsDeviceMacBundle");
            assertEquals(1, refs.size());
            assertEquals("Lx/A;", refs.get(0).classDescriptor());
            assertEquals("a", refs.get(0).name());
            assertArrayEquals(new String[0], refs.get(0).parameters());
        } finally {
            Files.deleteIfExists(apk);
        }
    }

    static class Stable {
        void refreshWearableDeviceList(java.util.List<?> a, java.util.List<?> b, String id) {}
    }

    static class Renamed {
        void a(java.util.List<?> a, java.util.List<?> b, String id) {}
    }

    static class Ambiguous {
        void a(String value) {}
        void b(String value) {}
    }

    @Test public void stableNameWinsStructuralResolution() throws Exception {
        Method method = HookResolver.resolveMethod(Stable.class, "refreshWearableDeviceList", void.class,
                java.util.List.class, java.util.List.class, String.class);
        assertEquals("refreshWearableDeviceList", method.getName());
    }

    @Test public void uniqueSignatureSurvivesMethodRename() throws Exception {
        Method method = HookResolver.resolveMethod(Renamed.class, "refreshWearableDeviceList", void.class,
                java.util.List.class, java.util.List.class, String.class);
        assertEquals("a", method.getName());
    }

    @Test public void ambiguousSignatureFailsClosed() {
        assertThrows(NoSuchMethodException.class,
                () -> HookResolver.resolveMethod(Ambiguous.class, "missing", void.class, String.class));
    }

    private static void put(ZipOutputStream zip, String name, byte[] bytes) throws IOException {
        zip.putNextEntry(new ZipEntry(name));
        zip.write(bytes);
        zip.closeEntry();
    }

    private static byte[] dexWithAnchoredMethod(String literal) {
        String[] strings = {"Lx/A;", "a", literal};
        int stringIdsOff = 0x70;
        int typeIdsOff = stringIdsOff + strings.length * 4;
        int protoIdsOff = typeIdsOff + 4;
        int methodIdsOff = protoIdsOff + 12;
        int classDefsOff = methodIdsOff + 8;
        int dataOff = classDefsOff + 32;
        byte[] dex = new byte[0x140];
        dex[0] = 'd';
        dex[1] = 'e';
        dex[2] = 'x';
        dex[3] = '\n';
        ByteBuffer buf = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(56, strings.length);
        buf.putInt(60, stringIdsOff);
        buf.putInt(64, 1);
        buf.putInt(68, typeIdsOff);
        buf.putInt(72, 1);
        buf.putInt(76, protoIdsOff);
        buf.putInt(88, 1);
        buf.putInt(92, methodIdsOff);
        buf.putInt(96, 1);
        buf.putInt(100, classDefsOff);

        int cursor = dataOff;
        for (int i = 0; i < strings.length; i++) {
            byte[] utf = strings[i].getBytes(StandardCharsets.UTF_8);
            buf.putInt(stringIdsOff + i * 4, cursor);
            dex[cursor++] = (byte) utf.length;
            System.arraycopy(utf, 0, dex, cursor, utf.length);
            cursor += utf.length;
            dex[cursor++] = 0;
        }

        buf.putInt(typeIdsOff, 0);
        buf.putInt(protoIdsOff, 0);
        buf.putInt(protoIdsOff + 4, 0);
        buf.putInt(protoIdsOff + 8, 0);
        buf.putShort(methodIdsOff, (short) 0);
        buf.putShort(methodIdsOff + 2, (short) 0);
        buf.putInt(methodIdsOff + 4, 1);

        int classDataOff = 0xd0;
        int codeOff = 0x100;
        buf.putInt(classDefsOff, 0);
        buf.putInt(classDefsOff + 4, 1);
        buf.putInt(classDefsOff + 8, -1);
        buf.putInt(classDefsOff + 24, classDataOff);

        int p = classDataOff;
        dex[p++] = 0;
        dex[p++] = 0;
        dex[p++] = 1;
        dex[p++] = 0;
        dex[p++] = 0;
        dex[p++] = 1;
        dex[p++] = (byte) 0x80;
        dex[p++] = 0x02;

        buf.putInt(codeOff + 12, 2);
        buf.putShort(codeOff + 16, (short) 0x001a);
        buf.putShort(codeOff + 18, (short) 2);
        return dex;
    }

    private static byte[] dex(String... descriptors) {
        int count = descriptors.length;
        int stringIdsOff = 0x70;
        int typeIdsOff = stringIdsOff + count * 4;
        int classDefsOff = typeIdsOff + count * 4;
        int dataOff = classDefsOff + count * 32;
        byte[][] items = new byte[count][];
        int[] at = new int[count];
        int cursor = dataOff;
        for (int i = 0; i < count; i++) {
            byte[] utf = descriptors[i].getBytes(StandardCharsets.UTF_8);
            if (utf.length >= 128) throw new IllegalArgumentException(descriptors[i]);
            byte[] item = new byte[utf.length + 2];
            item[0] = (byte) utf.length;
            System.arraycopy(utf, 0, item, 1, utf.length);
            items[i] = item;
            at[i] = cursor;
            cursor += item.length;
        }
        byte[] dex = new byte[cursor];
        dex[0] = 'd';
        dex[1] = 'e';
        dex[2] = 'x';
        dex[3] = '\n';
        ByteBuffer buf = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(56, count);
        buf.putInt(60, stringIdsOff);
        buf.putInt(64, count);
        buf.putInt(68, typeIdsOff);
        buf.putInt(96, count);
        buf.putInt(100, classDefsOff);
        for (int i = 0; i < count; i++) {
            buf.putInt(stringIdsOff + i * 4, at[i]);
            buf.putInt(typeIdsOff + i * 4, i);
            buf.putInt(classDefsOff + i * 32, i);
            System.arraycopy(items[i], 0, dex, at[i], items[i].length);
        }
        return dex;
    }
}
