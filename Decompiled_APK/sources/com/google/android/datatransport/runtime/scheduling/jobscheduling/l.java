package com.google.android.datatransport.runtime.scheduling.jobscheduling;

import com.google.android.datatransport.runtime.r;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class l implements com.google.android.datatransport.runtime.dagger.internal.b {
    public final javax.inject.a a;
    public final javax.inject.a b;
    public final r c;
    public final javax.inject.a d;

    public l(javax.inject.a aVar, javax.inject.a aVar2, r rVar, javax.inject.a aVar3) {
        this.a = aVar;
        this.b = aVar2;
        this.c = rVar;
        this.d = aVar3;
    }

    @Override // javax.inject.a
    public final Object get() {
        return new k((Executor) this.a.get(), (com.google.android.datatransport.runtime.scheduling.persistence.d) this.b.get(), (c) this.c.get(), (com.google.android.datatransport.runtime.synchronization.b) this.d.get());
    }
}
