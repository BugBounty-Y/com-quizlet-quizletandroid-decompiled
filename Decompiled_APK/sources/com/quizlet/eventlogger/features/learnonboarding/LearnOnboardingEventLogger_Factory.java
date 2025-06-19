package com.quizlet.eventlogger.features.learnonboarding;

import com.quizlet.eventlogger.EventLogger;

/* loaded from: classes2.dex */
public final class LearnOnboardingEventLogger_Factory implements dagger.internal.c {
    private final dagger.internal.c eventLoggerProvider;

    public LearnOnboardingEventLogger_Factory(dagger.internal.c cVar) {
        this.eventLoggerProvider = cVar;
    }

    @Override // javax.inject.a
    public LearnOnboardingEventLogger get() {
        return new LearnOnboardingEventLogger((EventLogger) this.eventLoggerProvider.get());
    }
}
