package com.quizlet.features.settings.data.interactor;

import kotlin.r;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.quizlet.data.repository.qclass.c k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(com.quizlet.data.repository.qclass.c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        super(cVar2);
        this.k = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objF = this.k.f(null, null, this);
        return objF == kotlin.coroutines.intrinsics.a.a ? objF : new r(objF);
    }
}
