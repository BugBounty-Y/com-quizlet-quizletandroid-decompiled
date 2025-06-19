package com.quizlet.local.ormlite.models.selectedterm;

import java.util.List;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.data.repository.login.a j;
    public List k;
    public /* synthetic */ Object l;
    public final /* synthetic */ com.quizlet.data.repository.login.a m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(com.quizlet.data.repository.login.a aVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.m(null, false, this);
    }
}
