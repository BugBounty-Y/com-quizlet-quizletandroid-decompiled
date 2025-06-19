package com.quizlet.features.folders.viewmodel.usecases;

/* loaded from: classes3.dex */
public final class t extends kotlin.coroutines.jvm.internal.c {
    public com.lyft.android.scissors.b j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ com.lyft.android.scissors.b m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(com.lyft.android.scissors.b bVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.n(null, this);
    }
}
