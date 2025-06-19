package com.google.android.datatransport.runtime.scheduling.jobscheduling;

import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class k {
    public final Executor a;
    public final com.google.android.datatransport.runtime.scheduling.persistence.d b;
    public final c c;
    public final com.google.android.datatransport.runtime.synchronization.b d;

    public k(Executor executor, com.google.android.datatransport.runtime.scheduling.persistence.d dVar, c cVar, com.google.android.datatransport.runtime.synchronization.b bVar) {
        this.a = executor;
        this.b = dVar;
        this.c = cVar;
        this.d = bVar;
    }
}
