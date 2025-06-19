package com.mayakapps.kache;

/* loaded from: classes2.dex */
public final class t extends kotlin.coroutines.jvm.internal.c {
    public u j;
    public kotlinx.coroutines.sync.c k;
    public long l;
    public /* synthetic */ Object m;
    public final /* synthetic */ u n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(u uVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = uVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.q(0L, this);
    }
}
