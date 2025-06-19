package com.quizlet.remote.model.qincentives;

import kotlin.coroutines.jvm.internal.c;

/* loaded from: classes3.dex */
public final class a extends c {
    public com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c cVar, c cVar2) {
        super(cVar2);
        this.l = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.f(this);
    }
}
