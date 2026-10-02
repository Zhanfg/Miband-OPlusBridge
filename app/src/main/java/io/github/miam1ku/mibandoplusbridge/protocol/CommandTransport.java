// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.protocol;

import java.util.concurrent.CompletionStage;
import nodomain.freeyourgadget.gadgetbridge.proto.xiaomi.XiaomiProto;

/** Minimal semantic command surface shared by native transport and Mi Fitness coexist relay. */
public interface CommandTransport {
    CompletionStage<Void> send(XiaomiProto.Command command);
    CompletionStage<XiaomiProto.Command> request(
            XiaomiProto.Command command, int responseType, int responseSubtype);
}
