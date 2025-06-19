package com.quizlet.data.interactor.search;

import kotlin.coroutines.jvm.internal.c;

/* loaded from: classes2.dex */
public final class b extends c {
    public com.quizlet.data.repository.searchexplanations.c j;
    public String k;
    public /* synthetic */ Object l;
    public final /* synthetic */ com.quizlet.data.repository.searchexplanations.c m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(com.quizlet.data.repository.searchexplanations.c cVar, c cVar2) {
        super(cVar2);
        this.m = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.i(null, this);
    }
}
