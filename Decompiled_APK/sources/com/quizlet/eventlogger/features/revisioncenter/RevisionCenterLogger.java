package com.quizlet.eventlogger.features.revisioncenter;

import androidx.lifecycle.u0;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.revisioncenter.RevisionCenterLog;
import com.quizlet.generated.enums.S0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class RevisionCenterLogger {

    @NotNull
    private static final a Companion = new a();

    @NotNull
    private final EventLogger eventLogger;

    public RevisionCenterLogger(@NotNull EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.eventLogger = eventLogger;
    }

    public final void a(S0 type, RevisionCenterSource source) {
        Intrinsics.checkNotNullParameter(type, "type");
        Intrinsics.checkNotNullParameter(source, "source");
        RevisionCenterLog.Companion companion = RevisionCenterLog.b;
        u0 payloadModifier = new u0(14, type, source);
        companion.getClass();
        Intrinsics.checkNotNullParameter("revision_center_opened", "action");
        Intrinsics.checkNotNullParameter(payloadModifier, "payloadModifier");
        RevisionCenterLog.Payload payload = new RevisionCenterLog.Payload(null, null, 3, null);
        payloadModifier.invoke(payload);
        RevisionCenterLog revisionCenterLog = new RevisionCenterLog(payload);
        revisionCenterLog.setAction("revision_center_opened");
        this.eventLogger.l(revisionCenterLog);
    }
}
