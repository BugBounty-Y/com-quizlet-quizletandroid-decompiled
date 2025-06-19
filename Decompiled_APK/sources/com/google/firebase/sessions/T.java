package com.google.firebase.sessions;

/* loaded from: classes2.dex */
public final class T extends kotlin.coroutines.jvm.internal.c {
    public U j;
    public /* synthetic */ Object k;
    public final /* synthetic */ U l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public T(U u, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = u;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return U.a(this.l, this);
    }
}
