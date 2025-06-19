package com.quizlet.data.interactor.folderstudymaterial;

import androidx.compose.foundation.gestures.l1;

/* loaded from: classes2.dex */
public final class p extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ l1 k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public p(l1 l1Var, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = l1Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objD = this.k.D(null, null, this);
        return objD == kotlin.coroutines.intrinsics.a.a ? objD : new kotlin.r(objD);
    }
}
