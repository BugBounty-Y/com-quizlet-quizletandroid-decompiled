package com.quizlet.data.interactor.learn;

import androidx.work.impl.model.l;
import kotlin.coroutines.jvm.internal.c;

/* loaded from: classes2.dex */
public final class a extends c {
    public l j;
    public /* synthetic */ Object k;
    public final /* synthetic */ l l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(l lVar, c cVar) {
        super(cVar);
        this.l = lVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.n(this);
    }
}
