package com.quizlet.features.notes.paywall;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ l k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(l lVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = lVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return l.A(this.k, this);
    }
}
