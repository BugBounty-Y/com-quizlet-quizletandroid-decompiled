package com.quizlet.features.folders.viewmodel.usecases;

/* loaded from: classes3.dex */
public final class m extends kotlin.coroutines.jvm.internal.c {
    public com.google.android.gms.internal.appset.e j;
    public long k;
    public /* synthetic */ Object l;
    public final /* synthetic */ com.google.android.gms.internal.appset.e m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(com.google.android.gms.internal.appset.e eVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.o(0L, this);
    }
}
