package com.mayakapps.kache;

/* loaded from: classes2.dex */
public final class l extends kotlin.coroutines.jvm.internal.c {
    public u j;
    public String k;
    public /* synthetic */ Object l;
    public final /* synthetic */ u m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(u uVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = uVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.c(null, this);
    }
}
