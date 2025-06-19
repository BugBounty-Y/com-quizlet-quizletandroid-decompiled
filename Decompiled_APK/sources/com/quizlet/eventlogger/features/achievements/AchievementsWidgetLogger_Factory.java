package com.quizlet.eventlogger.features.achievements;

import com.quizlet.eventlogger.EventLogger;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class AchievementsWidgetLogger_Factory implements c {
    private final c eventLoggerProvider;

    public AchievementsWidgetLogger_Factory(c cVar) {
        this.eventLoggerProvider = cVar;
    }

    @Override // javax.inject.a
    public AchievementsWidgetLogger get() {
        return new AchievementsWidgetLogger((EventLogger) this.eventLoggerProvider.get());
    }
}
