package com.perimeterx.mobile_sdk.session;

/* loaded from: classes2.dex */
public final class t extends kotlin.coroutines.jvm.internal.c {
    public d j;
    public com.perimeterx.mobile_sdk.api_data.j k;
    public /* synthetic */ Object l;
    public final /* synthetic */ d m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(d dVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.b(null, this);
    }
}
