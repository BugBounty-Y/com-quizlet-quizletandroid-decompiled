package com.quizlet.remote.model.selectedterm;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.data.interactor.set.c j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.quizlet.data.interactor.set.c l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(com.quizlet.data.interactor.set.c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        super(cVar2);
        this.l = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.q(0L, 0L, 0L, 0, false, this);
    }
}
