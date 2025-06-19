package com.quizlet.features.questiontypes.fitb.usecases;

import kotlin.coroutines.jvm.internal.c;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final class a extends c {
    public com.quizlet.data.repository.login.a j;
    public Function0 k;
    public Function0 l;
    public /* synthetic */ Object m;
    public final /* synthetic */ com.quizlet.data.repository.login.a n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(com.quizlet.data.repository.login.a aVar, c cVar) {
        super(cVar);
        this.n = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.g(null, null, null, null, this);
    }
}
