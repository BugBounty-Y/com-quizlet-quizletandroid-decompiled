package com.perimeterx.mobile_sdk.session;

/* loaded from: classes2.dex */
public final class u extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ d k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u(d dVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.i(null, null, null, this);
    }
}
