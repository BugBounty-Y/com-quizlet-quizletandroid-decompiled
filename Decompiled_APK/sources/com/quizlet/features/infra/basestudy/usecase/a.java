package com.quizlet.features.infra.basestudy.usecase;

import com.quizlet.generated.enums.P;

/* loaded from: classes3.dex */
public final class a extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public Object k;
    public P l;
    public boolean m;
    public boolean n;
    public boolean o;
    public long p;
    public /* synthetic */ Object q;
    public final /* synthetic */ b r;
    public int s;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(b bVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.r = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.q = obj;
        this.s |= Integer.MIN_VALUE;
        return this.r.a(null, 0L, false, this);
    }
}
