package com.quizlet.data.interactor.folder;

import com.google.android.gms.measurement.internal.J;

/* loaded from: classes2.dex */
public final class g extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ J k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(J j, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objF = this.k.f(null, null, 0L, 0L, this);
        return objF == kotlin.coroutines.intrinsics.a.a ? objF : new kotlin.r(objF);
    }
}
