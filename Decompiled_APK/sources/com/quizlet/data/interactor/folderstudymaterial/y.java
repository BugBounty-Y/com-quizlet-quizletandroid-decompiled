package com.quizlet.data.interactor.folderstudymaterial;

/* loaded from: classes2.dex */
public final class y extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ z k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public y(z zVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = zVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objC = this.k.c(0L, null, null, this);
        return objC == kotlin.coroutines.intrinsics.a.a ? objC : new kotlin.r(objC);
    }
}
