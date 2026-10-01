// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.hook;

import java.lang.reflect.Method;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public final class HookResolverTest {
    private static final class Fixture {
        private String stable(int value) { return Integer.toString(value); }
        private long moved(String value) { return value.length(); }
    }

    private static final class Ambiguous {
        private long first(String value) { return value.length(); }
        private long second(String value) { return value.length() + 1; }
    }

    private static final class NamedFixture {
        private void refreshView(Object event) {}
        private void refreshView(Object first, Object second) {}
    }

    private static final class NamedAmbiguous {
        private void refreshView(Object event) {}
        private int refreshView(String event) { return event.length(); }
    }

    @Test public void stableNameIsFastPathAndSignatureCanRecoverRenames() throws Exception {
        Method stable = HookResolver.resolveMethod(Fixture.class, "stable", String.class, int.class);
        assertEquals("stable", stable.getName());

        Method moved = HookResolver.resolveMethod(Fixture.class, "oldName", long.class, String.class);
        assertEquals("moved", moved.getName());
    }

    @Test public void ambiguousSignatureFailsClosed() {
        assertThrows(NoSuchMethodException.class, () ->
                HookResolver.resolveMethod(Ambiguous.class, "oldName", long.class, String.class));
    }

    @Test public void namedMethodCanExposeMovedParameterTypeWithoutGuessingIt() throws Exception {
        Method method = HookResolver.resolveNamedMethod(NamedFixture.class, "refreshView", 1, void.class);
        assertEquals(Object.class, method.getParameterTypes()[0]);
    }

    @Test public void namedMethodAmbiguityFailsClosed() {
        assertThrows(NoSuchMethodException.class, () ->
                HookResolver.resolveNamedMethod(NamedAmbiguous.class, "refreshView", 1, null));
    }
}
