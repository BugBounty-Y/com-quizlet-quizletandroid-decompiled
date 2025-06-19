package com.quizlet.login.common.interactors;

import com.google.android.gms.internal.ads.C1721Kc;

/* loaded from: classes3.dex */
public final class q extends kotlin.coroutines.jvm.internal.c {
    public C1721Kc j;
    public String k;
    public /* synthetic */ Object l;
    public final /* synthetic */ C1721Kc m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(C1721Kc c1721Kc, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = c1721Kc;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.f(null, null, this);
    }
}
