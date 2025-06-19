package com.quizlet.eventlogger.features.learnonboarding;

import com.quizlet.eventlogger.EventLogger;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class LearnOnboardingEventLogger {

    @NotNull
    private final EventLogger eventLogger;

    public LearnOnboardingEventLogger(@NotNull EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.eventLogger = eventLogger;
    }

    public final void a(LearnOnboardingEventLog learnOnboardingEventLog) {
        this.eventLogger.l(learnOnboardingEventLog);
    }
}
