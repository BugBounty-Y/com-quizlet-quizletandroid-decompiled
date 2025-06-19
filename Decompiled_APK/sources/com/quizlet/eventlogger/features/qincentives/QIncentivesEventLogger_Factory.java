package com.quizlet.eventlogger.features.qincentives;

import com.quizlet.eventlogger.EventLogger;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class QIncentivesEventLogger_Factory implements c {
    private final c eventLoggerProvider;

    public QIncentivesEventLogger_Factory(c cVar) {
        this.eventLoggerProvider = cVar;
    }

    @Override // javax.inject.a
    public QIncentivesEventLogger get() {
        return new QIncentivesEventLogger((EventLogger) this.eventLoggerProvider.get());
    }
}
