package com.quizlet.features.setpage.usecases;

import androidx.work.impl.model.n;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ n k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(n nVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = nVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.d(0L, null, this);
    }
}
