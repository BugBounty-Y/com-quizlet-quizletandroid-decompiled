package com.quizlet.data.interactor.notes;

import com.google.firebase.messaging.p;
import com.quizlet.data.model.R1;

/* loaded from: classes2.dex */
public final class g extends kotlin.coroutines.jvm.internal.c {
    public R1 j;
    public /* synthetic */ Object k;
    public final /* synthetic */ p l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(p pVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = pVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.t(null, this);
    }
}
