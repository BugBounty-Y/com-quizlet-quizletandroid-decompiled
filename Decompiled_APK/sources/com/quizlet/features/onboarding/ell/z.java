package com.quizlet.features.onboarding.ell;

/* loaded from: classes3.dex */
public final class z extends kotlin.coroutines.jvm.internal.c {
    public B j;
    public u k;
    public /* synthetic */ Object l;
    public final /* synthetic */ B m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public z(B b, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = b;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return B.A(this.m, false, null, this);
    }
}
