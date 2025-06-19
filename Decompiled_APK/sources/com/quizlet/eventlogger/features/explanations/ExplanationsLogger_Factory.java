package com.quizlet.eventlogger.features.explanations;

import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.study.StudyFunnelEventLogger;

/* loaded from: classes2.dex */
public final class ExplanationsLogger_Factory implements dagger.internal.c {
    private final dagger.internal.c eventLoggerProvider;
    private final dagger.internal.c studyFunnelEventLoggerProvider;

    public ExplanationsLogger_Factory(dagger.internal.c cVar, dagger.internal.c cVar2) {
        this.eventLoggerProvider = cVar;
        this.studyFunnelEventLoggerProvider = cVar2;
    }

    @Override // javax.inject.a
    public ExplanationsLogger get() {
        return new ExplanationsLogger((EventLogger) this.eventLoggerProvider.get(), (StudyFunnelEventLogger) this.studyFunnelEventLoggerProvider.get());
    }
}
