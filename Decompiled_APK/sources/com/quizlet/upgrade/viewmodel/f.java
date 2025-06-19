package com.quizlet.upgrade.viewmodel;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.c {
    public h j;
    public com.quizlet.billing.model.b k;
    public /* synthetic */ Object l;
    public final /* synthetic */ h m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(h hVar, kotlin.coroutines.h hVar2) {
        super(hVar2);
        this.m = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return h.B(this.m, null, this);
    }
}
