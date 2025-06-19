package com.quizlet.data.repository.folder;

import kotlin.r;

/* loaded from: classes2.dex */
public final class c extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ i k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(i iVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objC = this.k.c(0L, null, this);
        return objC == kotlin.coroutines.intrinsics.a.a ? objC : new r(objC);
    }
}
