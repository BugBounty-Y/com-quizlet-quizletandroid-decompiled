package com.quizlet.local.datastore.preferences;

/* loaded from: classes3.dex */
public final class I extends kotlin.coroutines.jvm.internal.c {
    public J j;
    public B k;
    public /* synthetic */ Object l;
    public final /* synthetic */ J m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public I(J j, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.d(null, this);
    }
}
