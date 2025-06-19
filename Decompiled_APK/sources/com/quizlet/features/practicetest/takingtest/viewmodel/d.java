package com.quizlet.features.practicetest.takingtest.viewmodel;

import androidx.lifecycle.p0;
import com.quizlet.features.practicetest.takingtest.data.F;
import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.A;
import kotlinx.coroutines.C5041z;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.a implements A {
    public final /* synthetic */ l a;
    public final /* synthetic */ F b;

    /* JADX WARN: Illegal instructions before constructor call */
    public d(l lVar, F f) {
        C5041z c5041z = C5041z.a;
        this.a = lVar;
        this.b = f;
        super(c5041z);
    }

    @Override // kotlinx.coroutines.A
    public final void handleException(CoroutineContext coroutineContext, Throwable th) {
        l lVar = this.a;
        E.A(p0.j(lVar), null, null, new e(th, lVar, this.b, null), 3);
    }
}
