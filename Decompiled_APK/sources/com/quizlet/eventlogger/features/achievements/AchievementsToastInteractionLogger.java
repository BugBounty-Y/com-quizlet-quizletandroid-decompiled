package com.quizlet.eventlogger.features.achievements;

import com.quizlet.eventlogger.EventLogger;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class AchievementsToastInteractionLogger {

    @NotNull
    private final EventLogger eventLogger;

    public AchievementsToastInteractionLogger(@NotNull EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.eventLogger = eventLogger;
    }

    public final void a(AchievementsToastInteractionEventLog achievementsToastInteractionEventLog) {
        this.eventLogger.l(achievementsToastInteractionEventLog);
    }
}
