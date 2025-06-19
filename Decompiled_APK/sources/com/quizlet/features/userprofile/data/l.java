package com.quizlet.features.userprofile.data;

/* loaded from: classes3.dex */
public final class l extends kotlin.coroutines.jvm.internal.c {
    public x j;
    public /* synthetic */ Object k;
    public final /* synthetic */ x l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(x xVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = xVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return x.A(this.l, this);
    }
}
