package com.quizlet.features.infra.google;

import kotlin.r;

/* loaded from: classes3.dex */
public final class c extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ e k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(e eVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objC = this.k.c(this);
        return objC == kotlin.coroutines.intrinsics.a.a ? objC : new r(objC);
    }
}
