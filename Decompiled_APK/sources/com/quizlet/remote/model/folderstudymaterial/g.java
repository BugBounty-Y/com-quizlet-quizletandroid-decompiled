package com.quizlet.remote.model.folderstudymaterial;

import kotlin.r;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.remote.model.base.a j;
    public /* synthetic */ Object k;
    public final /* synthetic */ j l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(j jVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = jVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        Object objC = this.l.c(null, null, null, this);
        return objC == kotlin.coroutines.intrinsics.a.a ? objC : new r(objC);
    }
}
