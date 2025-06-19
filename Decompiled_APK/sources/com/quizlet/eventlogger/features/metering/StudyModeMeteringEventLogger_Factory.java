package com.quizlet.eventlogger.features.metering;

import com.quizlet.eventlogger.EventLogger;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class StudyModeMeteringEventLogger_Factory implements c {
    private final c eventLoggerProvider;

    public StudyModeMeteringEventLogger_Factory(c cVar) {
        this.eventLoggerProvider = cVar;
    }

    @Override // javax.inject.a
    public StudyModeMeteringEventLogger get() {
        return new StudyModeMeteringEventLogger((EventLogger) this.eventLoggerProvider.get());
    }
}
