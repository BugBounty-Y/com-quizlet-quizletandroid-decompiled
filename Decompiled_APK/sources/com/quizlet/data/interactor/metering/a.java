package com.quizlet.data.interactor.metering;

import com.quizlet.generated.enums.P;

/* loaded from: classes2.dex */
public final class a extends kotlin.coroutines.jvm.internal.c {
    public b j;
    public Long k;
    public P l;
    public long m;
    public /* synthetic */ Object n;
    public final /* synthetic */ b o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(b bVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return this.o.a(0L, null, null, false, this);
    }
}
