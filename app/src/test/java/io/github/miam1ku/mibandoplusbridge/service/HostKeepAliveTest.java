// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.service;

import org.junit.Test;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

/** Root shell wake paths stay disabled in the runtime. */
public final class HostKeepAliveTest {
    @Test public void legacyShellCommandsAreNeverExecuted() {
        assertNotNull(OwnershipController.rootStartCommand(
                "io.github.miam1ku.mibandoplusbridge",
                "io.github.miam1ku.mibandoplusbridge.service.BandLiveService", true));
        assertFalse(OwnershipController.rootStart(
                "io.github.miam1ku.mibandoplusbridge",
                "io.github.miam1ku.mibandoplusbridge.service.BandLiveService", true));
        assertFalse(OwnershipController.rootStart(
                "com.heytap.health", "com.heytap.health.rpc.host.HealthRpcMsgService", false));
    }
}
