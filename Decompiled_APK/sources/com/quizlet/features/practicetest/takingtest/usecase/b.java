package com.quizlet.features.practicetest.takingtest.usecase;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public /* synthetic */ Object k;
    public final /* synthetic */ f l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(f fVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.a(null, 0, null, this);
    }
}
