package com.quizlet.eventlogger.features.studymodes;

import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.studymodes.StudyModeEventLogger;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class StudyModeEventLogger_Factory_Factory implements c {
    private final c eventLoggerProvider;

    public StudyModeEventLogger_Factory_Factory(c cVar) {
        this.eventLoggerProvider = cVar;
    }

    @Override // javax.inject.a
    public StudyModeEventLogger.Factory get() {
        return new StudyModeEventLogger.Factory((EventLogger) this.eventLoggerProvider.get());
    }
}
