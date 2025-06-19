package com.quizlet.eventlogger.features.autolaunch;

import com.quizlet.eventlogger.EventLogger;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class AutoLaunchEventLogger {

    @NotNull
    private final EventLogger eventLogger;

    public AutoLaunchEventLogger(@NotNull EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.eventLogger = eventLogger;
    }

    public final void a(AutoLaunchEventLog autoLaunchEventLog) {
        this.eventLogger.l(autoLaunchEventLog);
    }
}
