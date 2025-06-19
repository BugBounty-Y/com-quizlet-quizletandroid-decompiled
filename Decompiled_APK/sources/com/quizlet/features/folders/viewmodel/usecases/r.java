package com.quizlet.features.folders.viewmodel.usecases;

/* loaded from: classes3.dex */
public final class r extends kotlin.coroutines.jvm.internal.c {
    public com.google.firebase.crashlytics.internal.common.j j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.google.firebase.crashlytics.internal.common.j l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(com.google.firebase.crashlytics.internal.common.j jVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = jVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        Object objJ = this.l.j(0L, null, null, this);
        return objJ == kotlin.coroutines.intrinsics.a.a ? objJ : new kotlin.r(objJ);
    }
}
