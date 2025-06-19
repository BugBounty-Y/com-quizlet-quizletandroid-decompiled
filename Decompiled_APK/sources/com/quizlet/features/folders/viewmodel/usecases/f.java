package com.quizlet.features.folders.viewmodel.usecases;

import com.google.android.gms.ads.internal.client.C1608n;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ C1608n k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(C1608n c1608n, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = c1608n;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.p(null, this);
    }
}
