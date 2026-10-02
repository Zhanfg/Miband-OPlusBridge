// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge;

import org.junit.Test;
import static org.junit.Assert.*;

public final class OHealthHostProfileTest {
    @Test public void verifiedFamiliesAreClassifiedExactly() {
        assertEquals(OHealthHostProfile.Family.V6_1_18,
                OHealthHostProfile.classify("6.1.18_9fe4116_260429", 0).family());
        assertEquals(OHealthHostProfile.Family.V6_9_37,
                OHealthHostProfile.classify("6.9.37", 6_093_700L).family());
        var newest = OHealthHostProfile.classify("6.9.40_f91e7bd_260930", 6_094_000L);
        assertEquals(OHealthHostProfile.Family.V6_9_40, newest.family());
        assertTrue(newest.vendorFocusDnd());
        assertTrue(newest.multiProcessMusic());
        assertTrue(newest.encryptedBleActivity());
    }

    @Test public void unknownBuildUsesAdaptiveCompatibilityWithoutClaimingVerification() {
        var unknown = OHealthHostProfile.classify("7.0.0", 7_000_000L);
        assertEquals(OHealthHostProfile.Family.UNKNOWN, unknown.family());
        assertFalse(unknown.verified());
        assertTrue(unknown.vendorFocusDnd());
        assertTrue(unknown.multiProcessMusic());
        assertTrue(unknown.encryptedBleActivity());
    }
}
