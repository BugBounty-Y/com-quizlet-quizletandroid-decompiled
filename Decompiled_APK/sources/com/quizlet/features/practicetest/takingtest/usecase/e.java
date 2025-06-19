package com.quizlet.features.practicetest.takingtest.usecase;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ f k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(f fVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.e(null, null, null, this);
    }
}
