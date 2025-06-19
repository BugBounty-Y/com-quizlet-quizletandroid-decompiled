package com.quizlet.learn.viewmodel;

import com.quizlet.learn.data.C4537b;

/* loaded from: classes3.dex */
public final class q extends kotlin.coroutines.jvm.internal.c {
    public G j;
    public C4537b k;
    public /* synthetic */ Object l;
    public final /* synthetic */ G m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(G g, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = g;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return G.B(this.m, null, null, null, false, this);
    }
}
