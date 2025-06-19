package com.quizlet.features.onboarding.ell;

import com.google.android.gms.measurement.internal.J;

/* loaded from: classes3.dex */
public final class r extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ J k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(J j, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.g(0L, this);
    }
}
