package com.perimeterx.mobile_sdk.session;

/* loaded from: classes2.dex */
public final class o extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public Object k;
    public Object l;
    public Object m;
    public Object n;
    public Object o;
    public Object p;
    public String q;
    public String r;
    public /* synthetic */ Object s;
    public final /* synthetic */ d t;
    public int u;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o(d dVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.t = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.s = obj;
        this.u |= Integer.MIN_VALUE;
        return this.t.a(null, null, null, this);
    }
}
