package com.quizlet.quizletandroid.initializers.app;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.data.repository.login.a j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.quizlet.data.repository.login.a l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(com.quizlet.data.repository.login.a aVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.h(this);
    }
}
