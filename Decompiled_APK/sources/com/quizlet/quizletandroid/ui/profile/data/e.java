package com.quizlet.quizletandroid.ui.profile.data;

import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.A;
import kotlinx.coroutines.C5041z;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.a implements A {
    public final /* synthetic */ h a;
    public final /* synthetic */ boolean b;

    /* JADX WARN: Illegal instructions before constructor call */
    public e(h hVar, boolean z) {
        C5041z c5041z = C5041z.a;
        this.a = hVar;
        this.b = z;
        super(c5041z);
    }

    @Override // kotlinx.coroutines.A
    public final void handleException(CoroutineContext coroutineContext, Throwable th) {
        timber.log.c.a.h(th);
        h hVar = this.a;
        hVar.k.j(hVar.B(this.b, true));
    }
}
