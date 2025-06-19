package com.google.android.datatransport.runtime.scheduling;

import com.google.android.datatransport.runtime.backends.f;
import com.google.android.datatransport.runtime.q;
import com.google.android.datatransport.runtime.scheduling.persistence.d;
import java.util.concurrent.Executor;
import java.util.logging.Logger;

/* loaded from: classes2.dex */
public final class a implements c {
    public static final Logger f = Logger.getLogger(q.class.getName());
    public final com.google.android.datatransport.runtime.scheduling.jobscheduling.c a;
    public final Executor b;
    public final f c;
    public final d d;
    public final com.google.android.datatransport.runtime.synchronization.b e;

    public a(Executor executor, f fVar, com.google.android.datatransport.runtime.scheduling.jobscheduling.c cVar, d dVar, com.google.android.datatransport.runtime.synchronization.b bVar) {
        this.b = executor;
        this.c = fVar;
        this.a = cVar;
        this.d = dVar;
        this.e = bVar;
    }
}
