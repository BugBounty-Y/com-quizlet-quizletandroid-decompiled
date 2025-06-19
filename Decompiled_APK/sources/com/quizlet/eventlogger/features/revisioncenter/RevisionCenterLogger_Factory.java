package com.quizlet.eventlogger.features.revisioncenter;

import com.quizlet.eventlogger.EventLogger;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class RevisionCenterLogger_Factory implements c {
    private final c eventLoggerProvider;

    public RevisionCenterLogger_Factory(c cVar) {
        this.eventLoggerProvider = cVar;
    }

    @Override // javax.inject.a
    public RevisionCenterLogger get() {
        return new RevisionCenterLogger((EventLogger) this.eventLoggerProvider.get());
    }
}
