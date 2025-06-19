package com.quizlet.search.data.blended;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.remote.model.set.d j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.quizlet.remote.model.set.d l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(com.quizlet.remote.model.set.d dVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.c(null, this);
    }
}
