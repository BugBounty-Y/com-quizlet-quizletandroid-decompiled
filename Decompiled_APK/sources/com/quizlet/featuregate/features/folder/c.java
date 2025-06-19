package com.quizlet.featuregate.features.folder;

import kotlin.coroutines.h;

/* loaded from: classes2.dex */
public final class c extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.data.repository.course.membership.c j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.quizlet.data.repository.course.membership.c l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(com.quizlet.data.repository.course.membership.c cVar, h hVar) {
        super(hVar);
        this.l = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.d(this);
    }
}
