// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.service;

import android.content.Context;
import android.util.Log;
import io.github.miam1ku.mibandoplusbridge.integration.PhoneAlarmProvider;
import io.github.miam1ku.mibandoplusbridge.notify.FindPhone;
import io.github.miam1ku.mibandoplusbridge.notify.NativeMusic;
import io.github.miam1ku.mibandoplusbridge.notify.PhoneDnd;
import io.github.miam1ku.mibandoplusbridge.protocol.BandDndCommand;
import io.github.miam1ku.mibandoplusbridge.protocol.BandNotificationCommand;
import io.github.miam1ku.mibandoplusbridge.protocol.BandSystemCommand;
import nodomain.freeyourgadget.gadgetbridge.proto.xiaomi.XiaomiProto;

/** Small inbound subset mirrored from Mi Fitness' official TYPE_PROTO channel. */
public final class CoexistEventRouter {
    private static volatile long lastDndSentNanos;

    private CoexistEventRouter() {}

    public static void noteDndSent() {
        lastDndSentNanos = System.nanoTime();
    }

    public static void accept(Context context, byte[] payload) {
        if (context == null || payload == null || payload.length == 0) return;
        final XiaomiProto.Command command;
        try {
            command = XiaomiProto.Command.parseFrom(payload);
        } catch (Exception malformed) {
            return;
        }

        int type = command.getType();
        int subtype = command.getSubtype();
        try {
            if (type == 10) {
                CoexistControlPlane.onCommand(context, command);
                return;
            }
            if (type == 18) {
                if (subtype == 0) NativeMusic.requestRefresh(context);
                NativeMusic.onBandCommand(context, command);
                return;
            }

            if (type == 2) {
                if (subtype == 78 || subtype == 79) {
                    CoexistControlPlane.onSleepCommand(context, command);
                    return;
                }
                if (subtype == 17) {
                    FindPhone.onBandCommand(context, command);
                    return;
                }
                if (subtype == 43) {
                    boolean on = PhoneDnd.blocksNotifications(PhoneDnd.currentFilter(context));
                    CoexistProtoRelay.send(context, BandDndCommand.phoneSilent(on));
                    return;
                }
                Boolean bandOn = BandDndCommand.manualState(command);
                if (bandOn != null && PhoneDnd.acceptBandManual(
                        bandOn, PhoneDnd.currentFilter(context),
                        lastDndSentNanos, System.nanoTime())) {
                    boolean applied = PhoneDnd.apply(context, bandOn);
                    Log.i("OplusBandBridge", "COEXIST_DND_FROM_BAND on=" + bandOn
                            + " applied=" + applied);
                }
                return;
            }

            if (type == 7 && subtype == 16 && command.hasNotification()
                    && command.getNotification().hasNotificationIconQuery()) {
                String pkg = command.getNotification().getNotificationIconQuery().getPackage();
                if (pkg != null && !pkg.isBlank()) {
                    CoexistProtoRelay.send(context, BandNotificationCommand.iconQueryReply(pkg));
                }
                return;
            }

            if (type == 17 && subtype == 16 && command.hasSchedule()
                    && command.getSchedule().hasPhoneAlarmOperation()) {
                int op = command.getSchedule().getPhoneAlarmOperation().getOpCode();
                int alarmId = command.getSchedule().getPhoneAlarmOperation().hasPhoneAlarm()
                        ? command.getSchedule().getPhoneAlarmOperation().getPhoneAlarm().getId() : -1;
                if (op == 1 || op == 2) PhoneAlarmProvider.offer(op, alarmId);
            }
        } catch (RuntimeException failure) {
            Log.i("OplusBandBridge", "COEXIST_EVENT_FAILED "
                    + failure.getClass().getSimpleName());
        }
    }
}
