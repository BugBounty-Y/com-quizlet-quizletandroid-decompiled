package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase;

import kotlin.r;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ i k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(i iVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objD = this.k.d(this);
        return objD == kotlin.coroutines.intrinsics.a.a ? objD : new r(objD);
    }
}
