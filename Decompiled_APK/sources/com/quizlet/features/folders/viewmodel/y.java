package com.quizlet.features.folders.viewmodel;

/* loaded from: classes3.dex */
public final class y extends kotlin.coroutines.jvm.internal.c {
    public N j;
    public Object k;
    public /* synthetic */ Object l;
    public final /* synthetic */ N m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public y(N n, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = n;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return N.E(this.m, null, this);
    }
}
