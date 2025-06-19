package com.quizlet.features.folders.viewmodel.usecases;

/* loaded from: classes3.dex */
public final class o extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.quizlet.data.interactor.folderwithcreator.m k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o(com.quizlet.data.interactor.folderwithcreator.m mVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.l(null, 0L, 0L, 0L, false, false, this);
    }
}
