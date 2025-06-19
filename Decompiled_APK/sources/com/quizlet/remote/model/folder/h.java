package com.quizlet.remote.model.folder;

import kotlin.r;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ p k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(p pVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = pVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objB = this.k.b(0L, null, this);
        return objB == kotlin.coroutines.intrinsics.a.a ? objB : new r(objB);
    }
}
