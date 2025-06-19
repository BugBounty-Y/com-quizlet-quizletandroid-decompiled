package com.quizlet.eventlogger.features.experimentation;

import com.quizlet.eventlogger.EventLogger;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class ExperimentEnrollmentLogger_Factory implements c {
    private final c eventLoggerProvider;

    public ExperimentEnrollmentLogger_Factory(c cVar) {
        this.eventLoggerProvider = cVar;
    }

    @Override // javax.inject.a
    public ExperimentEnrollmentLogger get() {
        return new ExperimentEnrollmentLogger((EventLogger) this.eventLoggerProvider.get());
    }
}
