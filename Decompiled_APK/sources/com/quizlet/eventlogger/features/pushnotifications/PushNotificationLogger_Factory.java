package com.quizlet.eventlogger.features.pushnotifications;

import com.quizlet.eventlogger.EventLogger;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class PushNotificationLogger_Factory implements c {
    private final c eventLoggerProvider;

    public PushNotificationLogger_Factory(c cVar) {
        this.eventLoggerProvider = cVar;
    }

    @Override // javax.inject.a
    public PushNotificationLogger get() {
        return new PushNotificationLogger((EventLogger) this.eventLoggerProvider.get());
    }
}
