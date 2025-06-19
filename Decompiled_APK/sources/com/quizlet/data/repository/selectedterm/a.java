package com.quizlet.data.repository.selectedterm;

import kotlin.r;

/* loaded from: classes2.dex */
public final class a extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ f k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(f fVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objA = f.a(this.k, 0L, 0L, null, this);
        return objA == kotlin.coroutines.intrinsics.a.a ? objA : new r(objA);
    }
}
