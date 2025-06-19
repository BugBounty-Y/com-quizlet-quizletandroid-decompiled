package com.google.firebase.sessions;

/* renamed from: com.google.firebase.sessions.z, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4003z extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public /* synthetic */ Object k;
    public final /* synthetic */ A l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4003z(A a, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = a;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.a(null, this);
    }
}
