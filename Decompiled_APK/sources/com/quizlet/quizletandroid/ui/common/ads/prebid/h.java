package com.quizlet.quizletandroid.ui.common.ads.prebid;

import kotlin.r;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ m k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(m mVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objA = m.a(this.k, 0, null, this);
        return objA == kotlin.coroutines.intrinsics.a.a ? objA : new r(objA);
    }
}
