package com.quizlet.data.interactor.folderstudymaterial;

/* loaded from: classes2.dex */
public final class k extends kotlin.coroutines.jvm.internal.c {
    public o j;
    public Object k;
    public long l;
    public /* synthetic */ Object m;
    public final /* synthetic */ o n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(o oVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = oVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return o.a(this.n, 0L, null, this);
    }
}
