package com.google.android.datatransport.runtime;

import android.content.Context;

/* loaded from: classes2.dex */
public final class r implements com.google.android.datatransport.runtime.dagger.internal.b {
    public final /* synthetic */ int a;
    public final com.google.android.datatransport.runtime.dagger.internal.b b;
    public final javax.inject.a c;
    public final com.google.android.datatransport.runtime.dagger.internal.b d;

    public /* synthetic */ r(com.google.android.datatransport.runtime.dagger.internal.b bVar, javax.inject.a aVar, com.google.android.datatransport.runtime.dagger.internal.b bVar2, int i) {
        this.a = i;
        this.b = bVar;
        this.c = aVar;
        this.d = bVar2;
    }

    @Override // javax.inject.a
    public final Object get() {
        switch (this.a) {
            case 0:
                return new q(new com.quizlet.shared.usecase.folderstudymaterials.c(8), new com.quizlet.shared.usecase.folderstudymaterials.b(8), (com.google.android.datatransport.runtime.scheduling.c) ((com.google.android.datatransport.runtime.scheduling.b) this.b).get(), (com.google.android.datatransport.runtime.scheduling.jobscheduling.i) ((com.google.android.datatransport.runtime.scheduling.jobscheduling.j) this.c).get(), (com.google.android.datatransport.runtime.scheduling.jobscheduling.k) ((com.google.android.datatransport.runtime.scheduling.jobscheduling.l) this.d).get());
            default:
                return new com.google.android.datatransport.runtime.scheduling.jobscheduling.c((Context) ((com.google.android.datatransport.runtime.backends.e) this.b).b, (com.google.android.datatransport.runtime.scheduling.persistence.d) this.c.get(), (com.google.android.datatransport.runtime.scheduling.jobscheduling.a) ((m) this.d).get());
        }
    }
}
