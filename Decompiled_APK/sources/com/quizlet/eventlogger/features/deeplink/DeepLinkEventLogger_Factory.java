package com.quizlet.eventlogger.features.deeplink;

import com.quizlet.eventlogger.EventLogger;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class DeepLinkEventLogger_Factory implements c {
    private final c eventLoggerProvider;

    public DeepLinkEventLogger_Factory(c cVar) {
        this.eventLoggerProvider = cVar;
    }

    @Override // javax.inject.a
    public DeepLinkEventLogger get() {
        return new DeepLinkEventLogger((EventLogger) this.eventLoggerProvider.get());
    }
}
