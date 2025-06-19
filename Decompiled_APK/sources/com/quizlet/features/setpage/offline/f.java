package com.quizlet.features.setpage.offline;

import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.c {
    public k j;
    public s0 k;
    public Object l;
    public long m;
    public boolean n;
    public /* synthetic */ Object o;
    public final /* synthetic */ k p;
    public int q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(k kVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.p = kVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.o = obj;
        this.q |= Integer.MIN_VALUE;
        return this.p.c(0L, false, this);
    }
}
