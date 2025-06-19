package com.quizlet.remote.model.folderstudymaterial;

import kotlin.r;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ j k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(j jVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = jVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objB = this.k.b(0L, null, false, false, null, this);
        return objB == kotlin.coroutines.intrinsics.a.a ? objB : new r(objB);
    }
}
