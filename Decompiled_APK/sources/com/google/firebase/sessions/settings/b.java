package com.google.firebase.sessions.settings;

/* loaded from: classes2.dex */
public final class b extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public kotlinx.coroutines.sync.a k;
    public /* synthetic */ Object l;
    public final /* synthetic */ e m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(e eVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.d(this);
    }
}
