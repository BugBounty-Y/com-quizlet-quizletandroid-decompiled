package com.perimeterx.mobile_sdk.session;

import kotlin.jvm.internal.J;

/* loaded from: classes2.dex */
public final class y extends kotlin.coroutines.jvm.internal.c {
    public d j;
    public J k;
    public kotlinx.coroutines.sync.c l;
    public /* synthetic */ Object m;
    public final /* synthetic */ d n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public y(d dVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.k(this);
    }
}
