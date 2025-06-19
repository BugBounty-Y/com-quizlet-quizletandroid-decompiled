package com.quizlet.eventlogger;

/* loaded from: classes2.dex */
public final class KmpEventLogger_Factory implements dagger.internal.c {
    private final dagger.internal.c eventLoggerProvider;

    public KmpEventLogger_Factory(dagger.internal.c cVar) {
        this.eventLoggerProvider = cVar;
    }

    @Override // javax.inject.a
    public KmpEventLogger get() {
        return new KmpEventLogger((EventLogger) this.eventLoggerProvider.get());
    }
}
