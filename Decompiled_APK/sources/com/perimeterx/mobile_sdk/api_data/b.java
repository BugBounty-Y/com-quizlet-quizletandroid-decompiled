package com.perimeterx.mobile_sdk.api_data;

/* loaded from: classes2.dex */
public final class b extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ d k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(d dVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.a(null, null, null, this);
    }
}
