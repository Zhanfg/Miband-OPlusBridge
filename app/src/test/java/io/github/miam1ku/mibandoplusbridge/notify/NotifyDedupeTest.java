// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.notify;

import org.junit.Test;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public final class NotifyDedupeTest {
    @Test public void duplicateWindowAndOrderedExpiryStayCorrect() {
        NotifyDedupe dedupe = new NotifyDedupe();
        assertTrue(dedupe.first("a", 0));
        assertFalse(dedupe.first("a", 1_000));
        assertTrue(dedupe.first("b", 1_500));
        assertTrue(dedupe.first("a", NotifyDedupe.WINDOW_MS + 1));
        assertFalse(dedupe.first("b", 2_000));
        assertFalse(dedupe.first("a", NotifyDedupe.WINDOW_MS + 500));
    }
}
