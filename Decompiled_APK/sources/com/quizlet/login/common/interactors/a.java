package com.quizlet.login.common.interactors;

import java.time.LocalDateTime;

/* loaded from: classes3.dex */
public final class a extends kotlin.coroutines.jvm.internal.c {
    public androidx.work.impl.model.c j;
    public LocalDateTime k;
    public /* synthetic */ Object l;
    public final /* synthetic */ androidx.work.impl.model.c m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(androidx.work.impl.model.c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        super(cVar2);
        this.m = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.p(0L, this);
    }
}
