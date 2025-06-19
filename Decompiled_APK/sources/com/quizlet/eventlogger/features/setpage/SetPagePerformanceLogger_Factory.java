package com.quizlet.eventlogger.features.setpage;

import com.google.firebase.perf.b;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class SetPagePerformanceLogger_Factory implements c {
    private final c firebasePerformanceProvider;

    public SetPagePerformanceLogger_Factory(c cVar) {
        this.firebasePerformanceProvider = cVar;
    }

    @Override // javax.inject.a
    public SetPagePerformanceLogger get() {
        return new SetPagePerformanceLogger((b) this.firebasePerformanceProvider.get());
    }
}
