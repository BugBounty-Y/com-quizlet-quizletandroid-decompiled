package com.quizlet.eventlogger.features.achievements;

import com.quizlet.eventlogger.EventLogger;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class AchievementsToastInteractionLogger_Factory implements c {
    private final c eventLoggerProvider;

    public AchievementsToastInteractionLogger_Factory(c cVar) {
        this.eventLoggerProvider = cVar;
    }

    @Override // javax.inject.a
    public AchievementsToastInteractionLogger get() {
        return new AchievementsToastInteractionLogger((EventLogger) this.eventLoggerProvider.get());
    }
}
