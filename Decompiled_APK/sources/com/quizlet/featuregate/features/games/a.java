package com.quizlet.featuregate.features.games;

import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.c;

/* loaded from: classes2.dex */
public final class a extends c {
    public com.quizlet.data.repository.folderset.c j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.quizlet.data.repository.folderset.c l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(com.quizlet.data.repository.folderset.c cVar, h hVar) {
        super(hVar);
        this.l = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.m(this);
    }
}
