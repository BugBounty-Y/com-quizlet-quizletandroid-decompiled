package com.quizlet.features.setpage.termlist.viewmodel;

import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.A;
import kotlinx.coroutines.C5041z;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.a implements A {
    public final /* synthetic */ j a;
    public final /* synthetic */ long b;

    /* JADX WARN: Illegal instructions before constructor call */
    public e(j jVar, long j) {
        C5041z c5041z = C5041z.a;
        this.a = jVar;
        this.b = j;
        super(c5041z);
    }

    @Override // kotlinx.coroutines.A
    public final void handleException(CoroutineContext coroutineContext, Throwable th) {
        timber.log.c.a.p(th);
        this.a.D(this.b, false);
    }
}
