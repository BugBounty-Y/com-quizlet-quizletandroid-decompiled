package com.quizlet.features.onboarding.ell;

import com.google.android.gms.measurement.internal.J;

/* loaded from: classes3.dex */
public final class t extends kotlin.coroutines.jvm.internal.c {
    public J j;
    public long k;
    public /* synthetic */ Object l;
    public final /* synthetic */ J m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(J j, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return J.a(this.m, 0L, this);
    }
}
