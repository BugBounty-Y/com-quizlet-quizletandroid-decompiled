package com.quizlet.edgy.ui.viewmodel;

/* loaded from: classes2.dex */
public final class L extends kotlin.coroutines.jvm.internal.c {
    public M j;
    public /* synthetic */ Object k;
    public final /* synthetic */ M l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public L(M m, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = m;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return M.B(this.l, this);
    }
}
