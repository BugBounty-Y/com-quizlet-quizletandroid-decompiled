package com.quizlet.local.datastore.preferences;

/* loaded from: classes3.dex */
public final class S extends kotlin.coroutines.jvm.internal.c {
    public androidx.datastore.preferences.core.f j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.lyft.android.scissors.b l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public S(com.lyft.android.scissors.b bVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.h(0L, this);
    }
}
