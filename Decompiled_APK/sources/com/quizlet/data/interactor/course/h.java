package com.quizlet.data.interactor.course;

import com.google.firebase.messaging.p;

/* loaded from: classes2.dex */
public final class h extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ p k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(p pVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = pVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.u(null, 0, this);
    }
}
