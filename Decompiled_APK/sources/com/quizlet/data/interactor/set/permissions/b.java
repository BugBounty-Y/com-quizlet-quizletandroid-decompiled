package com.quizlet.data.interactor.set.permissions;

import java.util.HashSet;

/* loaded from: classes2.dex */
public final class b extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.data.repository.user.a j;
    public String k;
    public HashSet l;
    public long m;
    public int n;
    public /* synthetic */ Object o;
    public final /* synthetic */ com.quizlet.data.repository.user.a p;
    public int q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(com.quizlet.data.repository.user.a aVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.p = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.o = obj;
        this.q |= Integer.MIN_VALUE;
        return this.p.f(0L, 0L, null, this);
    }
}
