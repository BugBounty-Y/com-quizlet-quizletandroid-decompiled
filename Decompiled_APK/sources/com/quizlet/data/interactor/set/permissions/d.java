package com.quizlet.data.interactor.set.permissions;

import java.util.HashSet;

/* loaded from: classes2.dex */
public final class d extends kotlin.coroutines.jvm.internal.c {
    public boolean j;
    public HashSet k;
    public com.quizlet.data.repository.user.a l;
    public /* synthetic */ Object m;
    public final /* synthetic */ com.quizlet.data.repository.user.a n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(com.quizlet.data.repository.user.a aVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.i(0L, false, null, this);
    }
}
