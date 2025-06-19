package com.quizlet.data.interactor.folderstudymaterial;

/* loaded from: classes2.dex */
public final class x extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ z k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public x(z zVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = zVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objB = this.k.b(null, null, null, this);
        return objB == kotlin.coroutines.intrinsics.a.a ? objB : new kotlin.r(objB);
    }
}
