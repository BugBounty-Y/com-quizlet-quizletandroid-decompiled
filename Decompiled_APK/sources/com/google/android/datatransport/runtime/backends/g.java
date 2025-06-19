package com.google.android.datatransport.runtime.backends;

import android.content.Context;
import com.google.android.datatransport.runtime.scheduling.persistence.i;

/* loaded from: classes2.dex */
public final class g implements com.google.android.datatransport.runtime.dagger.internal.b {
    public final /* synthetic */ int a;
    public final com.google.android.datatransport.runtime.dagger.internal.b b;
    public final javax.inject.a c;

    public /* synthetic */ g(com.google.android.datatransport.runtime.dagger.internal.b bVar, javax.inject.a aVar, int i) {
        this.a = i;
        this.b = bVar;
        this.c = aVar;
    }

    @Override // javax.inject.a
    public final Object get() {
        switch (this.a) {
            case 0:
                return new f((Context) ((e) this.b).b, (d) ((e) this.c).get());
            default:
                return new com.google.android.datatransport.runtime.scheduling.persistence.g(new com.quizlet.shared.usecase.folderstudymaterials.c(8), new com.quizlet.shared.usecase.folderstudymaterials.b(8), com.google.android.datatransport.runtime.scheduling.persistence.a.f, (i) ((e) this.b).get(), this.c);
        }
    }
}
