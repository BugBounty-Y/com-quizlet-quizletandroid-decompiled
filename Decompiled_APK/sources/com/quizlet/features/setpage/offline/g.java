package com.quizlet.features.setpage.offline;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.c {
    public k j;
    public long k;
    public boolean l;
    public /* synthetic */ Object m;
    public final /* synthetic */ k n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(k kVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = kVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.d(0L, false, false, this);
    }
}
