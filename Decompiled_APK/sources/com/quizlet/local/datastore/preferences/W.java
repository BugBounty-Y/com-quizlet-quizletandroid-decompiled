package com.quizlet.local.datastore.preferences;

/* loaded from: classes3.dex */
public final class W extends kotlin.coroutines.jvm.internal.c {
    public com.lyft.android.scissors.b j;
    public androidx.datastore.preferences.core.f k;
    public /* synthetic */ Object l;
    public final /* synthetic */ com.lyft.android.scissors.b m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public W(com.lyft.android.scissors.b bVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.l(0L, this);
    }
}
