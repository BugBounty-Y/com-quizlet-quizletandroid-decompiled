package com.quizlet.eventlogger.features.study;

import com.quizlet.eventlogger.EventLogger;
import dagger.internal.c;

/* renamed from: com.quizlet.eventlogger.features.study.StudySessionQuestionEventLogger_Factory, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4213StudySessionQuestionEventLogger_Factory implements c {
    private final c eventLoggerProvider;

    public C4213StudySessionQuestionEventLogger_Factory(c cVar) {
        this.eventLoggerProvider = cVar;
    }

    @Override // javax.inject.a
    public StudySessionQuestionEventLogger get() {
        return new StudySessionQuestionEventLogger((EventLogger) this.eventLoggerProvider.get());
    }
}
