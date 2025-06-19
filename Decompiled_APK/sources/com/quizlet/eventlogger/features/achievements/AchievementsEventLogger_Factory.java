package com.quizlet.eventlogger.features.achievements;

import com.quizlet.eventlogger.EventLogger;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class AchievementsEventLogger_Factory implements c {
    private final c eventLoggerProvider;

    public AchievementsEventLogger_Factory(c cVar) {
        this.eventLoggerProvider = cVar;
    }

    @Override // javax.inject.a
    public AchievementsEventLogger get() {
        return new AchievementsEventLogger((EventLogger) this.eventLoggerProvider.get());
    }
}
