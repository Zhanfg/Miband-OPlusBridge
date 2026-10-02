// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.hook;

import java.lang.reflect.Member;

/**
 * Small source-compatible callback surface used while moving the module to
 * libxposed API 102. It preserves the before/after semantics used by the old
 * hooks without loading any legacy Xposed classes at runtime.
 */
public abstract class XC_MethodHook {
    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {}
    protected void afterHookedMethod(MethodHookParam param) throws Throwable {}

    public static final class MethodHookParam {
        public Member method;
        public Object thisObject;
        public Object[] args;
        private Object result;
        private Throwable throwable;
        private boolean returnEarly;

        public Object getResult() { return result; }
        public Throwable getThrowable() { return throwable; }
        public boolean hasThrowable() { return throwable != null; }

        public void setResult(Object value) {
            result = value;
            throwable = null;
            returnEarly = true;
        }

        public void setThrowable(Throwable value) {
            throwable = value;
            returnEarly = true;
        }

        boolean returnEarly() { return returnEarly; }
        void resultFromOriginal(Object value) { result = value; }
        void throwableFromOriginal(Throwable value) { throwable = value; }
    }
}
