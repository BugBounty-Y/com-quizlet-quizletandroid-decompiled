package com.quizlet.data.interactor.metering;

import com.quizlet.data.model.C4179x0;

/* loaded from: classes2.dex */
public final class c extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.data.interactor.school.b j;
    public C4179x0 k;
    public /* synthetic */ Object l;
    public final /* synthetic */ com.quizlet.data.interactor.school.b m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(com.quizlet.data.interactor.school.b bVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.n(null, false, this);
    }
}
