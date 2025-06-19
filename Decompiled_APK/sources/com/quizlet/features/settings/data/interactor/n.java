package com.quizlet.features.settings.data.interactor;

import kotlin.r;

/* loaded from: classes3.dex */
public final class n extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.quizlet.data.repository.qclass.c k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(com.quizlet.data.repository.qclass.c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        super(cVar2);
        this.k = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objQ = this.k.q(null, this);
        return objQ == kotlin.coroutines.intrinsics.a.a ? objQ : new r(objQ);
    }
}
