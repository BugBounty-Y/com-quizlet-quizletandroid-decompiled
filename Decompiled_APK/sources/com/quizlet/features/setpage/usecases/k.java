package com.quizlet.features.setpage.usecases;

import androidx.work.impl.model.n;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ n k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(n nVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = nVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.e(0L, this);
    }
}
