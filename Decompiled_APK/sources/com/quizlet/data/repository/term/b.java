package com.quizlet.data.repository.term;

import kotlin.r;

/* loaded from: classes2.dex */
public final class b extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ g k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(g gVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objA = g.a(this.k, 0L, null, this);
        return objA == kotlin.coroutines.intrinsics.a.a ? objA : new r(objA);
    }
}
