package com.quizlet.remote.model.foldertoadd;

import kotlin.coroutines.jvm.internal.c;
import kotlin.r;

/* loaded from: classes3.dex */
public final class a extends c {
    public com.quizlet.data.repository.searchexplanations.c j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.quizlet.data.repository.searchexplanations.c l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(com.quizlet.data.repository.searchexplanations.c cVar, c cVar2) {
        super(cVar2);
        this.l = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        Object objG = this.l.g(null, null, null, this);
        return objG == kotlin.coroutines.intrinsics.a.a ? objG : new r(objG);
    }
}
