package com.quizlet.features.setpage.offline;

/* loaded from: classes3.dex */
public final class c extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ k k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(k kVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = kVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return k.a(this.k, 0L, false, this);
    }
}
