package com.quizlet.login.common.interactors;

/* loaded from: classes3.dex */
public final class y extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.data.repository.achievements.h j;
    public String k;
    public /* synthetic */ Object l;
    public final /* synthetic */ com.quizlet.data.repository.achievements.h m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public y(com.quizlet.data.repository.achievements.h hVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.d(null, null, null, this);
    }
}
