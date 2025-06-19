package com.quizlet.data.repository.metering;

/* loaded from: classes2.dex */
public final class g extends kotlin.coroutines.jvm.internal.c {
    public j j;
    public String k;
    public /* synthetic */ Object l;
    public final /* synthetic */ j m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(j jVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = jVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return j.b(this.m, null, 0L, null, null, null, this);
    }
}
