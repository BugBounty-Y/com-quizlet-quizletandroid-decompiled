package com.quizlet.eventlogger.features.autolaunch;

import com.quizlet.eventlogger.EventLogger;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class AutoLaunchEventLogger_Factory implements c {
    private final c eventLoggerProvider;

    public AutoLaunchEventLogger_Factory(c cVar) {
        this.eventLoggerProvider = cVar;
    }

    @Override // javax.inject.a
    public AutoLaunchEventLogger get() {
        return new AutoLaunchEventLogger((EventLogger) this.eventLoggerProvider.get());
    }
}
