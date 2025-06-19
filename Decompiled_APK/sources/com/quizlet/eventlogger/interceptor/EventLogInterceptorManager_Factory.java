package com.quizlet.eventlogger.interceptor;

import dagger.internal.c;

/* loaded from: classes2.dex */
public final class EventLogInterceptorManager_Factory implements c {
    private final c flipperEventLogInterceptorProvider;

    public EventLogInterceptorManager_Factory(c cVar) {
        this.flipperEventLogInterceptorProvider = cVar;
    }

    @Override // javax.inject.a
    public EventLogInterceptorManager get() {
        return new EventLogInterceptorManager((IEventLogInterceptor) this.flipperEventLogInterceptorProvider.get());
    }
}
