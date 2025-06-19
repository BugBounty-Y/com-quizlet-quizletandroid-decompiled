package com.mayakapps.kache;

/* loaded from: classes2.dex */
public final class D extends kotlin.coroutines.jvm.internal.c {
    public H j;
    public kotlinx.coroutines.sync.a k;
    public /* synthetic */ Object l;
    public final /* synthetic */ H m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D(H h, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = h;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return H.d(this.m, this);
    }
}
