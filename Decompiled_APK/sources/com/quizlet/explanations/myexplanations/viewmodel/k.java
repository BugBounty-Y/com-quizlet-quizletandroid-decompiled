package com.quizlet.explanations.myexplanations.viewmodel;

/* loaded from: classes2.dex */
public final class k extends kotlin.coroutines.jvm.internal.c {
    public m j;
    public Object k;
    public Integer l;
    public /* synthetic */ Object m;
    public final /* synthetic */ m n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(m mVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return m.D(this.n, null, this);
    }
}
