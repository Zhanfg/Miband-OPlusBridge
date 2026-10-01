// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.ui;

/** First-run step from LSPosed hook readiness, binding, transport profile and registration. */
public final class SetupProgress {
    public enum Step { HOOK, IMPORT, PROFILE, ADD, DONE }

    public final boolean hookReady;
    public final boolean hasBinding;
    public final boolean hasProfile;
    public final boolean registered;
    public final boolean nativeOwned;
    public final boolean accountConfirmed;

    public SetupProgress(boolean hookReady, boolean hasBinding, boolean hasProfile,
                         boolean registered, boolean nativeOwned, boolean accountConfirmed) {
        this.hookReady = hookReady;
        this.hasBinding = hasBinding;
        this.hasProfile = hasProfile;
        this.registered = registered;
        this.nativeOwned = nativeOwned;
        this.accountConfirmed = accountConfirmed;
    }

    public Step current() {
        if (!hookReady) return Step.HOOK;
        if (!hasBinding) return Step.IMPORT;
        if (!hasProfile) return Step.PROFILE;
        if (!registered || !nativeOwned) return Step.ADD;
        return Step.DONE;
    }

    public boolean showChecklist() {
        return current() != Step.DONE;
    }

    public String primaryLabel() {
        return switch (current()) {
            case HOOK -> "检查 LSPosed";
            case IMPORT -> "导入绑定";
            case PROFILE -> "采集连接参数";
            case ADD -> "添加到健康";
            case DONE -> "立即同步";
        };
    }

    public String primaryHint() {
        return switch (current()) {
            case HOOK -> "在 LSPosed 中启用模块并勾选小米运动健康、OHealth、我的设备和系统时钟；然后打开一次小米运动健康。";
            case IMPORT -> "选择已配对手环，打开小米运动健康点开该设备。120 秒内同时导入绑定并记录连接参数。";
            case PROFILE -> "打开小米运动健康并点开这只手环，让它重新连上。120 秒内记录连接参数。";
            case ADD -> "由 LSPosed 在小米运动健康进程内让出这只手环的蓝牙 transport，再由桥接接管；不需要 Root shell。";
            case DONE -> "";
        };
    }
}
