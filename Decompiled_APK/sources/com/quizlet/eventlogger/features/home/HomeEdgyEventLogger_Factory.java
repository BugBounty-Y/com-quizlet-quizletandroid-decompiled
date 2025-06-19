package com.quizlet.eventlogger.features.home;

import com.quizlet.eventlogger.EventLogger;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class HomeEdgyEventLogger_Factory implements c {
    private final c eventLoggerProvider;

    public HomeEdgyEventLogger_Factory(c cVar) {
        this.eventLoggerProvider = cVar;
    }

    @Override // javax.inject.a
    public HomeEdgyEventLogger get() {
        return new HomeEdgyEventLogger((EventLogger) this.eventLoggerProvider.get());
    }
}
