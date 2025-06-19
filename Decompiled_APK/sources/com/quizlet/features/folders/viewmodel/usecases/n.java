package com.quizlet.features.folders.viewmodel.usecases;

/* loaded from: classes3.dex */
public final class n extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.data.interactor.folderwithcreator.m j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.quizlet.data.interactor.folderwithcreator.m l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(com.quizlet.data.interactor.folderwithcreator.m mVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        Object objF = this.l.f(0L, this);
        return objF == kotlin.coroutines.intrinsics.a.a ? objF : new kotlin.r(objF);
    }
}
