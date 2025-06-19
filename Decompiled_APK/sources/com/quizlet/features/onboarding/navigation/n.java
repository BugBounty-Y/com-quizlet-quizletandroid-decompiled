package com.quizlet.features.onboarding.navigation;

/* loaded from: classes3.dex */
public final class n extends kotlin.coroutines.jvm.internal.c {
    public p j;
    public l k;
    public /* synthetic */ Object l;
    public final /* synthetic */ p m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(p pVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = pVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.A(null, this);
    }
}
