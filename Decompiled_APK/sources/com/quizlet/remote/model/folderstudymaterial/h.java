package com.quizlet.remote.model.folderstudymaterial;

import kotlin.r;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.remote.model.base.a j;
    public /* synthetic */ Object k;
    public final /* synthetic */ j l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(j jVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = jVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        Object objD = this.l.d(null, null, null, null, this);
        return objD == kotlin.coroutines.intrinsics.a.a ? objD : new r(objD);
    }
}
