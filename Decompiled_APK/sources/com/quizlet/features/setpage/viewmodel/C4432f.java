package com.quizlet.features.setpage.viewmodel;

import com.quizlet.features.infra.basestudy.data.models.MeteredValue;

/* renamed from: com.quizlet.features.setpage.viewmodel.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4432f extends kotlin.coroutines.jvm.internal.c {
    public P j;
    public MeteredValue k;
    public /* synthetic */ Object l;
    public final /* synthetic */ P m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4432f(P p, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return P.B(this.m, null, this);
    }
}
