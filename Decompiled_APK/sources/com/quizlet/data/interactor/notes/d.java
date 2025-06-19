package com.quizlet.data.interactor.notes;

/* loaded from: classes2.dex */
public final class d extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.quizlet.data.interactor.achievements.f k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(com.quizlet.data.interactor.achievements.f fVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.i(null, this);
    }
}
