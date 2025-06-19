package com.quizlet.remote.model.folderstudymaterial;

import kotlin.r;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.data.repository.qclass.c j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.quizlet.data.repository.qclass.c l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(com.quizlet.data.repository.qclass.c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        super(cVar2);
        this.l = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        Object objJ = this.l.j(null, this);
        return objJ == kotlin.coroutines.intrinsics.a.a ? objJ : new r(objJ);
    }
}
