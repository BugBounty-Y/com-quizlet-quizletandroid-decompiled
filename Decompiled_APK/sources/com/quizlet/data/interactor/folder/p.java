package com.quizlet.data.interactor.folder;

/* loaded from: classes2.dex */
public final class p extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.data.interactor.school.b j;
    public long k;
    public /* synthetic */ Object l;
    public final /* synthetic */ com.quizlet.data.interactor.school.b m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public p(com.quizlet.data.interactor.school.b bVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        Object objO = this.m.o(0L, this);
        return objO == kotlin.coroutines.intrinsics.a.a ? objO : new kotlin.r(objO);
    }
}
