package com.quizlet.features.setpage.usecases;

/* loaded from: classes3.dex */
public final class c extends kotlin.coroutines.jvm.internal.c {
    public Long j;
    public /* synthetic */ Object k;
    public final /* synthetic */ androidx.compose.runtime.internal.j l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(androidx.compose.runtime.internal.j jVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = jVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.n(null, this);
    }
}
