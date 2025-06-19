package com.quizlet.eventlogger.features.study;

import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.study.StudySessionQuestionEventLogger;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class StudySessionQuestionEventLogger_Factory_Factory implements c {
    private final c eventLoggerProvider;

    public StudySessionQuestionEventLogger_Factory_Factory(c cVar) {
        this.eventLoggerProvider = cVar;
    }

    @Override // javax.inject.a
    public StudySessionQuestionEventLogger.Factory get() {
        return new StudySessionQuestionEventLogger.Factory((EventLogger) this.eventLoggerProvider.get());
    }
}
