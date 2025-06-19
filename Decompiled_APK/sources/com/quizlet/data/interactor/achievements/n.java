package com.quizlet.data.interactor.achievements;

import kotlin.r;

/* loaded from: classes2.dex */
public final class n extends kotlin.coroutines.jvm.internal.c {
    public String j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.google.firebase.crashlytics.internal.common.j l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(com.google.firebase.crashlytics.internal.common.j jVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = jVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        Object objH = this.l.h(null, this);
        return objH == kotlin.coroutines.intrinsics.a.a ? objH : new r(objH);
    }
}
