package com.google.android.datatransport.runtime.scheduling;

import com.google.android.datatransport.runtime.backends.f;
import com.google.android.datatransport.runtime.r;
import com.google.android.datatransport.runtime.scheduling.persistence.d;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class b implements com.google.android.datatransport.runtime.dagger.internal.b {
    public final javax.inject.a a;
    public final javax.inject.a b;
    public final r c;
    public final javax.inject.a d;
    public final javax.inject.a e;

    public b(javax.inject.a aVar, javax.inject.a aVar2, r rVar, javax.inject.a aVar3, javax.inject.a aVar4) {
        this.a = aVar;
        this.b = aVar2;
        this.c = rVar;
        this.d = aVar3;
        this.e = aVar4;
    }

    @Override // javax.inject.a
    public final Object get() {
        return new a((Executor) this.a.get(), (f) this.b.get(), (com.google.android.datatransport.runtime.scheduling.jobscheduling.c) this.c.get(), (d) this.d.get(), (com.google.android.datatransport.runtime.synchronization.b) this.e.get());
    }
}
