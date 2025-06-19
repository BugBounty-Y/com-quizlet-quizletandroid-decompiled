package com.perimeterx.mobile_sdk.session;

/* loaded from: classes2.dex */
public final class p extends kotlin.coroutines.jvm.internal.c {
    public d j;
    public Object k;
    public Object l;
    public kotlinx.coroutines.sync.c m;
    public /* synthetic */ Object n;
    public final /* synthetic */ d o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public p(d dVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return this.o.c(null, null, this);
    }
}
