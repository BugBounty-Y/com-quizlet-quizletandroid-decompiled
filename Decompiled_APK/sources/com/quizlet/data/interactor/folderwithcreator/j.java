package com.quizlet.data.interactor.folderwithcreator;

/* loaded from: classes2.dex */
public final class j extends kotlin.coroutines.jvm.internal.c {
    public m j;
    public long k;
    public /* synthetic */ Object l;
    public final /* synthetic */ m m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(m mVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.j(0L, this);
    }
}
