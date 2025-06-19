package com.quizlet.features.infra.basestudy.usecase;

import com.quizlet.generated.enums.P;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.data.interactor.metering.b j;
    public Long k;
    public P l;
    public long m;
    public /* synthetic */ Object n;
    public final /* synthetic */ com.quizlet.data.interactor.set.c o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(com.quizlet.data.interactor.set.c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        super(cVar2);
        this.o = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return this.o.o(0L, this);
    }
}
