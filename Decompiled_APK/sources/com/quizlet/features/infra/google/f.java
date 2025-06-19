package com.quizlet.features.infra.google;

import kotlin.r;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.google.android.material.floatingactionbutton.c k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(com.google.android.material.floatingactionbutton.c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        super(cVar2);
        this.k = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objP = this.k.p(this);
        return objP == kotlin.coroutines.intrinsics.a.a ? objP : new r(objP);
    }
}
