package com.quizlet.eventlogger.features.practicetest;

import com.quizlet.eventlogger.EventLogger;

/* loaded from: classes2.dex */
public final class PracticeTestEventLogger_Factory implements dagger.internal.c {
    private final dagger.internal.c eventLoggerProvider;

    public PracticeTestEventLogger_Factory(dagger.internal.c cVar) {
        this.eventLoggerProvider = cVar;
    }

    @Override // javax.inject.a
    public PracticeTestEventLogger get() {
        return new PracticeTestEventLogger((EventLogger) this.eventLoggerProvider.get());
    }
}
