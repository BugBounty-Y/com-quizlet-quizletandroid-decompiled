package com.quizlet.remote.model.practicetests;

import com.google.android.gms.internal.ads.C3;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ C3 k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(C3 c3, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = c3;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.d(null, 0L, false, this);
    }
}
