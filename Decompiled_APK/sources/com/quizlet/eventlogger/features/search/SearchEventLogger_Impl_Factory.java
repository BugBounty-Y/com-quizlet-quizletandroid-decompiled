package com.quizlet.eventlogger.features.search;

import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class SearchEventLogger_Impl_Factory implements c {
    private final c eventLoggerProvider;

    public SearchEventLogger_Impl_Factory(c cVar) {
        this.eventLoggerProvider = cVar;
    }

    @Override // javax.inject.a
    public SearchEventLogger.Impl get() {
        return new SearchEventLogger.Impl((EventLogger) this.eventLoggerProvider.get());
    }
}
