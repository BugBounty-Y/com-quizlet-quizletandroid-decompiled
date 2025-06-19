package com.quizlet.login.common.interactors;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.c {
    public androidx.compose.runtime.internal.j j;
    public k k;
    public /* synthetic */ Object l;
    public final /* synthetic */ androidx.compose.runtime.internal.j m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(androidx.compose.runtime.internal.j jVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = jVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.u(null, null, this);
    }
}
