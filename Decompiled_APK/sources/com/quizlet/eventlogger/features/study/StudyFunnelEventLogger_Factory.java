package com.quizlet.eventlogger.features.study;

import com.quizlet.eventlogger.EventLogger;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class StudyFunnelEventLogger_Factory implements c {
    private final c eventLoggerProvider;

    public StudyFunnelEventLogger_Factory(c cVar) {
        this.eventLoggerProvider = cVar;
    }

    @Override // javax.inject.a
    public StudyFunnelEventLogger get() {
        return new StudyFunnelEventLogger((EventLogger) this.eventLoggerProvider.get());
    }
}
