package com.mayakapps.kache;

/* loaded from: classes2.dex */
public final class I extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ K k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public I(K k, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = k;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.a(null, this);
    }
}
