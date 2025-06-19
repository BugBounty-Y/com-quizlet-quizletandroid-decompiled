package com.quizlet.features.folders.viewmodel;

/* loaded from: classes3.dex */
public final class t extends kotlin.coroutines.jvm.internal.c {
    public N j;
    public /* synthetic */ Object k;
    public final /* synthetic */ N l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(N n, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = n;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return N.B(this.l, null, this);
    }
}
