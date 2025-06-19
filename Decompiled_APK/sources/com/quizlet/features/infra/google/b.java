package com.quizlet.features.infra.google;

import kotlin.r;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ e k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(e eVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objB = this.k.b(this);
        return objB == kotlin.coroutines.intrinsics.a.a ? objB : new r(objB);
    }
}
