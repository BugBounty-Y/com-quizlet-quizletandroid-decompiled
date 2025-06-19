package com.braze.communication.dust;

/* loaded from: classes.dex */
public final class b extends kotlin.coroutines.jvm.internal.c {
    public h a;
    public /* synthetic */ Object b;
    public final /* synthetic */ h c;
    public int d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(h hVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.c = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.b = obj;
        this.d |= Integer.MIN_VALUE;
        return this.c.a(this);
    }
}
