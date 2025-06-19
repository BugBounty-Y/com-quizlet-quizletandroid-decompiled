package com.quizlet.quizletandroid.ui.library;

/* loaded from: classes3.dex */
public final class L extends kotlin.coroutines.jvm.internal.c {
    public c0 j;
    public com.quizlet.ui.models.content.carditem.f k;
    public /* synthetic */ Object l;
    public final /* synthetic */ c0 m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public L(c0 c0Var, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = c0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return c0.A(this.m, null, this);
    }
}
