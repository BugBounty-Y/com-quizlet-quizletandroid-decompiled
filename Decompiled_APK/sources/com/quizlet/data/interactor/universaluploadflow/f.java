package com.quizlet.data.interactor.universaluploadflow;

import androidx.work.impl.model.l;

/* loaded from: classes2.dex */
public final class f extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ l k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(l lVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = lVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.m(null, this);
    }
}
