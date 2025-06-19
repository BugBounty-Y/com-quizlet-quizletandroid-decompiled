package com.quizlet.eventlogger.features.folder;

import com.quizlet.eventlogger.EventLogger;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class FolderLogger_Factory implements c {
    private final c eventLoggerProvider;

    public FolderLogger_Factory(c cVar) {
        this.eventLoggerProvider = cVar;
    }

    @Override // javax.inject.a
    public FolderLogger get() {
        return new FolderLogger((EventLogger) this.eventLoggerProvider.get());
    }
}
