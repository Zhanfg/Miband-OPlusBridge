// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.service;

import android.content.Context;
import android.os.UserManager;
import io.github.miam1ku.mibandoplusbridge.HostIdentity;
import io.github.miam1ku.mibandoplusbridge.data.LocalPrefs;
import io.github.miam1ku.mibandoplusbridge.integration.OwnershipProvider;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Reversible transport ownership without root.
 *
 * NATIVE means the LSPosed hook inside Mi Fitness blocks/relinquishes only the
 * imported band's Bluetooth transport. The Xiaomi package itself remains enabled.
 */
public final class OwnershipController {
    private static final ReentrantReadWriteLock GATE = new ReentrantReadWriteLock(true);
    private final Context context;
    private final LocalPrefs state;

    public static void beginNativeSession() { GATE.readLock().lock(); }
    public static void endNativeSession() { GATE.readLock().unlock(); }

    public static final class Failure extends Exception {
        public final String code;
        public Failure(String code) { super(code); this.code = code; }
    }

    public OwnershipController(Context context) {
        this.context = context.getApplicationContext() == null ? context : context.getApplicationContext();
        state = LocalPrefs.open(this.context, "ownership");
    }

    public String mode() { return state.getString("mode", "OFFICIAL"); }

    public synchronized boolean nativeReady() {
        return "NATIVE".equals(mode()) && state.getBoolean("hookExclusive", false)
                && context.getSystemService(UserManager.class).isUserUnlocked();
    }

    /** Kept source-compatible while the UI migrates away from the old KernelSU gate. */
    @Deprecated public boolean probeRoot() { return true; }

    public synchronized void takeOver() throws Failure {
        GATE.writeLock().lock();
        try {
            requireUnlocked();
            if (!HostIdentity.installed(context, HostIdentity.MI_PACKAGE)) {
                throw new Failure("HOST_VERSION_UNSUPPORTED");
            }
            if (nativeReady()) return;
            long generation = state.getLong("generation", 0) + 1;
            if (!state.edit()
                    .putBoolean("transitionPending", true)
                    .putString("mode", "NATIVE")
                    .putBoolean("hookExclusive", true)
                    .putBoolean("ownsDisable", false)
                    .putBoolean("officialRestored", false)
                    .putLong("generation", generation)
                    .commit()) {
                throw new Failure("OWNERSHIP_STORAGE_FAILED");
            }
            if (!state.edit().putBoolean("transitionPending", false).commit()) {
                throw new Failure("OWNERSHIP_STORAGE_FAILED");
            }
            publish();
        } finally {
            GATE.writeLock().unlock();
        }
    }

    public synchronized void restoreOfficial() throws Failure {
        GATE.writeLock().lock();
        try {
            requireUnlocked();
            long generation = state.getLong("generation", 0) + 1;
            if (!state.edit()
                    .putString("mode", "OFFICIAL")
                    .putBoolean("hookExclusive", false)
                    .putBoolean("ownsDisable", false)
                    .putBoolean("transitionPending", false)
                    .putBoolean("officialRestored", true)
                    .remove("originalEnabled")
                    .remove("dozeAdded")
                    .putLong("generation", generation)
                    .commit()) {
                throw new Failure("OWNERSHIP_STORAGE_FAILED");
            }
            publish();
        } finally {
            GATE.writeLock().unlock();
        }
    }

    public synchronized boolean restoreIfModuleInvalid() throws Failure {
        if (!context.getSystemService(UserManager.class).isUserUnlocked()) return false;
        if (!"NATIVE".equals(mode()) || nativeReady()) return false;
        restoreOfficial();
        return true;
    }

    private void publish() {
        try { context.getContentResolver().notifyChange(OwnershipProvider.URI, null); }
        catch (RuntimeException ignored) {}
    }

    private void requireUnlocked() throws Failure {
        if (!context.getSystemService(UserManager.class).isUserUnlocked()) throw new Failure("USER_LOCKED");
    }

    /** Legacy test helper only; no command is executed anywhere in the rootless runtime. */
    static String rootStartCommand(String packageName, String className, boolean foreground) {
        if (foreground && "io.github.miam1ku.mibandoplusbridge".equals(packageName)
                && "io.github.miam1ku.mibandoplusbridge.service.BandLiveService".equals(className)) {
            return "am start-foreground-service --user 0 -n " + packageName + "/" + className;
        }
        if (!foreground && "com.heytap.health".equals(packageName)
                && "com.heytap.health.rpc.host.HealthRpcMsgService".equals(className)) {
            return "am start-service --user 0 -n " + packageName + "/" + className;
        }
        return null;
    }

    static boolean rootStart(String packageName, String className, boolean foreground) {
        return false;
    }
}
