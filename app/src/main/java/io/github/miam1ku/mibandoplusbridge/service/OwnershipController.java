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
    private static final Object ACK_MONITOR = new Object();
    private static final long ACK_TIMEOUT_MS = 1_500;
    private static long acknowledgedGeneration = -1;
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
                && !state.getBoolean("transitionPending", false)
                && context.getSystemService(UserManager.class).isUserUnlocked();
    }

    /** Normal operating mode: Mi Fitness keeps the authenticated transport. */
    public synchronized boolean coexistReady() {
        return "COEXIST".equals(mode()) && !state.getBoolean("hookExclusive", false)
                && !state.getBoolean("transitionPending", false)
                && context.getSystemService(UserManager.class).isUserUnlocked();
    }

    public synchronized boolean managedReady() {
        return coexistReady() || nativeReady();
    }

    /** Called only by the authenticated OwnershipProvider hookAck path. */
    public static void noteHookAck(long generation) {
        if (generation < 0) return;
        synchronized (ACK_MONITOR) {
            if (generation > acknowledgedGeneration) acknowledgedGeneration = generation;
            ACK_MONITOR.notifyAll();
        }
    }

    public synchronized void enableCoexist() throws Failure {
        GATE.writeLock().lock();
        try {
            requireUnlocked();
            if (!HostIdentity.installed(context, HostIdentity.MI_PACKAGE)) {
                throw new Failure("HOST_VERSION_UNSUPPORTED");
            }
            if (coexistReady()) return;
            long generation = state.getLong("generation", 0) + 1;
            if (!state.edit()
                    .putBoolean("transitionPending", true)
                    .putString("mode", "COEXIST")
                    .putBoolean("hookExclusive", false)
                    .putBoolean("ownsDisable", false)
                    .putBoolean("officialRestored", false)
                    .putLong("generation", generation)
                    .commit()) {
                throw new Failure("OWNERSHIP_STORAGE_FAILED");
            }
            publish();
            if (!awaitHookAck(generation, ACK_TIMEOUT_MS)) {
                rollbackToOfficial(generation);
                throw new Failure("LSP_OWNERSHIP_ACK_TIMEOUT");
            }
            if (!state.edit().putBoolean("transitionPending", false).commit()) {
                rollbackToOfficial(generation);
                throw new Failure("OWNERSHIP_STORAGE_FAILED");
            }
        } finally {
            GATE.writeLock().unlock();
        }
    }

    /** Event-only sync request while Mi Fitness remains the transport owner. */
    public synchronized long requestCoexistSync() throws Failure {
        GATE.writeLock().lock();
        try {
            requireUnlocked();
            if (!coexistReady()) throw new Failure("COEXIST_NOT_READY");
            long generation = state.getLong("generation", 0) + 1;
            if (!state.edit().putLong("generation", generation).commit()) {
                throw new Failure("OWNERSHIP_STORAGE_FAILED");
            }
            publish();
            if (!awaitHookAck(generation, ACK_TIMEOUT_MS)) {
                throw new Failure("LSP_OWNERSHIP_ACK_TIMEOUT");
            }
            return generation;
        } finally {
            GATE.writeLock().unlock();
        }
    }

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
            publish();
            if (!awaitHookAck(generation, ACK_TIMEOUT_MS)) {
                rollbackTakeover(generation);
                throw new Failure("LSP_OWNERSHIP_ACK_TIMEOUT");
            }
            if (!state.edit().putBoolean("transitionPending", false).commit()) {
                rollbackTakeover(generation);
                throw new Failure("OWNERSHIP_STORAGE_FAILED");
            }
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

    static boolean awaitHookAck(long generation, long timeoutMs) {
        long deadline = System.nanoTime()
                + java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(Math.max(1, timeoutMs));
        synchronized (ACK_MONITOR) {
            while (acknowledgedGeneration < generation) {
                long remainingNanos = deadline - System.nanoTime();
                if (remainingNanos <= 0) return false;
                long waitMs = Math.max(1,
                        java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(remainingNanos));
                try {
                    ACK_MONITOR.wait(waitMs);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
            return true;
        }
    }

    private void rollbackTakeover(long failedGeneration) {
        rollbackToOfficial(failedGeneration);
    }

    private void rollbackToOfficial(long failedGeneration) {
        long rollbackGeneration = Math.max(state.getLong("generation", 0), failedGeneration) + 1;
        state.edit()
                .putString("mode", "OFFICIAL")
                .putBoolean("hookExclusive", false)
                .putBoolean("ownsDisable", false)
                .putBoolean("transitionPending", false)
                .putBoolean("officialRestored", true)
                .putLong("generation", rollbackGeneration)
                .commit();
        publish();
    }

    private void publish() {
        try { context.getContentResolver().notifyChange(OwnershipProvider.URI, null); }
        catch (RuntimeException ignored) {}
    }

    private void requireUnlocked() throws Failure {
        if (!context.getSystemService(UserManager.class).isUserUnlocked()) throw new Failure("USER_LOCKED");
    }


}
