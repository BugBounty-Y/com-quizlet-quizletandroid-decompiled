package com.quizlet.learn.usecase.onboarding;

import kotlin.coroutines.jvm.internal.c;

/* loaded from: classes3.dex */
public final class a extends c {
    public com.quizlet.data.repository.course.membership.c j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ com.quizlet.data.repository.course.membership.c m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(com.quizlet.data.repository.course.membership.c cVar, c cVar2) {
        super(cVar2);
        this.m = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.j(null, this);
    }
}
