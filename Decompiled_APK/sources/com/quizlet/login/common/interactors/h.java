package com.quizlet.login.common.interactors;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.c {
    public androidx.compose.runtime.internal.j j;
    public com.quizlet.login.authentication.data.i k;
    public String l;
    public String m;
    public /* synthetic */ Object n;
    public final /* synthetic */ androidx.compose.runtime.internal.j o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(androidx.compose.runtime.internal.j jVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = jVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return this.o.s(null, null, null, this);
    }
}
