package com.quizlet.shared.quizletapi.base;

/* loaded from: classes3.dex */
public final class a extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ c k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        super(cVar2);
        this.k = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return c.c(this.k, null, this);
    }
}
