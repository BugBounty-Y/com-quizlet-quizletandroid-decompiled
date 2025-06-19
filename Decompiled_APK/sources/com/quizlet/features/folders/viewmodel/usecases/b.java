package com.quizlet.features.folders.viewmodel.usecases;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.data.repository.activitycenter.b j;
    public long k;
    public /* synthetic */ Object l;
    public final /* synthetic */ com.quizlet.data.repository.activitycenter.b m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(com.quizlet.data.repository.activitycenter.b bVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.i(0L, false, this);
    }
}
