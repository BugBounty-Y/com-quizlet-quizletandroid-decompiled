package com.perimeterx.mobile_sdk.session;

/* loaded from: classes2.dex */
public final class w extends kotlin.coroutines.jvm.internal.c {
    public d j;
    public com.perimeterx.mobile_sdk.api_data.j k;
    public kotlinx.coroutines.sync.c l;
    public /* synthetic */ Object m;
    public final /* synthetic */ d n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w(d dVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.j(null, this);
    }
}
