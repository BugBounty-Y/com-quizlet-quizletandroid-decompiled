package com.quizlet.features.practicetest.takingtest.viewmodel;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.c {
    public l j;
    public String k;
    public /* synthetic */ Object l;
    public final /* synthetic */ l m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(l lVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = lVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return l.A(this.m, this);
    }
}
