package com.quizlet.features.onboarding.flashcards;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.c {
    public n j;
    public /* synthetic */ Object k;
    public final /* synthetic */ n l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(n nVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = nVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return n.A(this.l, this);
    }
}
