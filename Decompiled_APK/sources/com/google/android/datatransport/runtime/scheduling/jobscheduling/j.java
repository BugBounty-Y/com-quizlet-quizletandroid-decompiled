package com.google.android.datatransport.runtime.scheduling.jobscheduling;

import android.content.Context;
import com.google.android.datatransport.runtime.r;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class j implements com.google.android.datatransport.runtime.dagger.internal.b {
    public final com.google.android.datatransport.runtime.backends.e a;
    public final javax.inject.a b;
    public final javax.inject.a c;
    public final r d;
    public final javax.inject.a e;
    public final javax.inject.a f;
    public final javax.inject.a g;

    public j(com.google.android.datatransport.runtime.backends.e eVar, javax.inject.a aVar, javax.inject.a aVar2, r rVar, javax.inject.a aVar3, javax.inject.a aVar4, javax.inject.a aVar5) {
        this.a = eVar;
        this.b = aVar;
        this.c = aVar2;
        this.d = rVar;
        this.e = aVar3;
        this.f = aVar4;
        this.g = aVar5;
    }

    @Override // javax.inject.a
    public final Object get() {
        return new i((Context) this.a.b, (com.google.android.datatransport.runtime.backends.f) this.b.get(), (com.google.android.datatransport.runtime.scheduling.persistence.d) this.c.get(), (c) this.d.get(), (Executor) this.e.get(), (com.google.android.datatransport.runtime.synchronization.b) this.f.get(), new com.quizlet.shared.usecase.folderstudymaterials.c(8), new com.quizlet.shared.usecase.folderstudymaterials.b(8), (com.google.android.datatransport.runtime.scheduling.persistence.c) this.g.get());
    }
}
