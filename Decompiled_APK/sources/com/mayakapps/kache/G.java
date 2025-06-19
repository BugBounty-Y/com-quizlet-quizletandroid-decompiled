package com.mayakapps.kache;

/* loaded from: classes2.dex */
public final class G extends kotlin.coroutines.jvm.internal.c {
    public H j;
    public String k;
    public kotlinx.coroutines.sync.c l;
    public /* synthetic */ Object m;
    public final /* synthetic */ H n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public G(H h, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = h;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return H.e(this.n, null, this);
    }
}
