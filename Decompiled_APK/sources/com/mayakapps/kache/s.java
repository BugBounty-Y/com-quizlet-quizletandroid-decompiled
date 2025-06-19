package com.mayakapps.kache;

/* loaded from: classes2.dex */
public final class s extends kotlin.coroutines.jvm.internal.c {
    public u j;
    public Object k;
    public kotlinx.coroutines.sync.c l;
    public /* synthetic */ Object m;
    public final /* synthetic */ u n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public s(u uVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = uVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.m(null, this);
    }
}
