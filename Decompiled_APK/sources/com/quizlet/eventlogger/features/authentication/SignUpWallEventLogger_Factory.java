package com.quizlet.eventlogger.features.authentication;

import com.quizlet.eventlogger.EventLogger;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class SignUpWallEventLogger_Factory implements c {
    private final c eventLoggerProvider;

    public SignUpWallEventLogger_Factory(c cVar) {
        this.eventLoggerProvider = cVar;
    }

    @Override // javax.inject.a
    public SignUpWallEventLogger get() {
        return new SignUpWallEventLogger((EventLogger) this.eventLoggerProvider.get());
    }
}
