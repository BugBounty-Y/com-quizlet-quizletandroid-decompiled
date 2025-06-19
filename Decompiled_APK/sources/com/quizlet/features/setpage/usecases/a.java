package com.quizlet.features.setpage.usecases;

/* loaded from: classes3.dex */
public final class a extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ androidx.compose.runtime.internal.j k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(androidx.compose.runtime.internal.j jVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = jVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.l(0L, null, this);
    }
}
