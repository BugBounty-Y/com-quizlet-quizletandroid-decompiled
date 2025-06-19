package com.quizlet.data.interactor.notes;

/* loaded from: classes2.dex */
public final class j extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.lyft.android.scissors.b k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(com.lyft.android.scissors.b bVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.m(null, null, this);
    }
}
