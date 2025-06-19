package com.quizlet.eventlogger.features.achievements;

import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.model.StandardizedEventLog;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class AchievementsEventLogger {

    @NotNull
    private final EventLogger eventLogger;

    public AchievementsEventLogger(@NotNull EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.eventLogger = eventLogger;
    }

    public final void a(StandardizedEventLog standardizedEventLog) {
        this.eventLogger.l(standardizedEventLog);
    }
}
