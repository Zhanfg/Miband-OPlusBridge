// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;

/** Small, explicit compatibility profile for verified OHealth builds. */
public final class OHealthHostProfile {
    public enum Family {
        V6_1_18,
        V6_9_37,
        V6_9_40,
        UNKNOWN
    }

    public record Profile(Family family, String versionName, long versionCode,
                          boolean verified, boolean vendorFocusDnd,
                          boolean multiProcessMusic, boolean encryptedBleActivity) {
        public String diagnostic() {
            return "family=" + family
                    + " version=" + (versionName == null ? "" : versionName)
                    + " code=" + versionCode
                    + " verified=" + verified
                    + " focusDnd=" + vendorFocusDnd
                    + " multiProcessMusic=" + multiProcessMusic
                    + " encryptedBleActivity=" + encryptedBleActivity;
        }
    }

    private OHealthHostProfile() {}

    public static Profile classify(String versionName, long versionCode) {
        String name = versionName == null ? "" : versionName;
        if (versionCode == 6_011_800L || name.startsWith("6.1.18")) {
            return new Profile(Family.V6_1_18, name, versionCode,
                    true, false, false, false);
        }
        if (versionCode == 6_093_700L || name.startsWith("6.9.37")) {
            return new Profile(Family.V6_9_37, name, versionCode,
                    true, false, false, false);
        }
        if (versionCode == 6_094_000L || name.startsWith("6.9.40")) {
            return new Profile(Family.V6_9_40, name, versionCode,
                    true, true, true, true);
        }
        return new Profile(Family.UNKNOWN, name, versionCode,
                false, true, true, true);
    }

    public static Profile detect(Context context) {
        if (context == null) return classify("", 0);
        try {
            PackageInfo info = context.getPackageManager().getPackageInfo(
                    HostIdentity.HEALTH_PACKAGE, 0);
            return classify(info.versionName, info.getLongVersionCode());
        } catch (PackageManager.NameNotFoundException missing) {
            return classify("", 0);
        }
    }
}
