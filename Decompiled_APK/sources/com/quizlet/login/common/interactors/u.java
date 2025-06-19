package com.quizlet.login.common.interactors;

/* loaded from: classes3.dex */
public final class u extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.data.interactor.progress.c j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.quizlet.data.interactor.progress.c l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u(com.quizlet.data.interactor.progress.c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        super(cVar2);
        this.l = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.g(null, this);
    }
}
