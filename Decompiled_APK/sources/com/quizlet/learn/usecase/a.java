package com.quizlet.learn.usecase;

import com.quizlet.generated.enums.P;

/* loaded from: classes3.dex */
public final class a extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public Object k;
    public com.quizlet.data.interactor.metering.b l;
    public Long m;
    public P n;
    public long o;
    public /* synthetic */ Object p;
    public final /* synthetic */ b q;
    public int r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(b bVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.q = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.p = obj;
        this.r |= Integer.MIN_VALUE;
        return this.q.a(0L, null, this);
    }
}
