package com.quizlet.remote.model.folderstudymaterial;

import kotlin.r;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.c {
    public m j;
    public /* synthetic */ Object k;
    public final /* synthetic */ m l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(m mVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        Object objA = this.l.a(0L, null, null, this);
        return objA == kotlin.coroutines.intrinsics.a.a ? objA : new r(objA);
    }
}
