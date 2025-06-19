package com.quizlet.features.folders.viewmodel.usecases;

import com.quizlet.data.model.AbstractC4119d0;

/* loaded from: classes3.dex */
public final class p extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.data.interactor.folderwithcreator.m j;
    public String k;
    public AbstractC4119d0 l;
    public long m;
    public long n;
    public long o;
    public boolean p;
    public /* synthetic */ Object q;
    public final /* synthetic */ com.quizlet.data.interactor.folderwithcreator.m r;
    public int s;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public p(com.quizlet.data.interactor.folderwithcreator.m mVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.r = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        this.q = obj;
        this.s |= Integer.MIN_VALUE;
        Object objN = this.r.n(0L, null, 0L, 0L, false, this);
        return objN == kotlin.coroutines.intrinsics.a.a ? objN : new kotlin.r(objN);
    }
}
