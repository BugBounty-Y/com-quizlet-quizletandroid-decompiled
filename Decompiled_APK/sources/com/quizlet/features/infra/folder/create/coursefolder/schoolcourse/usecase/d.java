package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase;

import kotlin.r;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.e k;
    public /* synthetic */ Object l;
    public final /* synthetic */ i m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(i iVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        Object objA = this.m.a(null, this);
        return objA == kotlin.coroutines.intrinsics.a.a ? objA : new r(objA);
    }
}
