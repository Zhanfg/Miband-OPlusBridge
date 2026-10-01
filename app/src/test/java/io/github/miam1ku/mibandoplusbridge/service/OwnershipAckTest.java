// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.service;

import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.Test;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public final class OwnershipAckTest {
    @Test public void ackWakesWaiterWithoutPolling() throws Exception {
        long generation = Long.MAX_VALUE - 1;
        var executor = Executors.newSingleThreadExecutor();
        try {
            var waiting = executor.submit(() -> OwnershipController.awaitHookAck(generation, 1_000));
            Thread.sleep(20);
            OwnershipController.noteHookAck(generation);
            assertTrue(waiting.get(1, TimeUnit.SECONDS));
        } finally {
            executor.shutdownNow();
        }
    }

    @Test public void missingFutureAckTimesOut() {
        assertFalse(OwnershipController.awaitHookAck(Long.MAX_VALUE, 20));
    }
}
