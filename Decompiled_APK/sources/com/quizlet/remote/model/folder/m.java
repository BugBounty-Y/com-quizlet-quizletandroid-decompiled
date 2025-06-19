package com.quizlet.remote.model.folder;

import kotlin.r;

/* loaded from: classes3.dex */
public final class m extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ p k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(p pVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = pVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objE = this.k.e(0L, this);
        return objE == kotlin.coroutines.intrinsics.a.a ? objE : new r(objE);
    }
}
