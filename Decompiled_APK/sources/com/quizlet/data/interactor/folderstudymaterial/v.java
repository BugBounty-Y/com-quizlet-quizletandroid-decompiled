package com.quizlet.data.interactor.folderstudymaterial;

/* loaded from: classes2.dex */
public final class v extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.onetrust.otpublishers.headless.UI.fragment.q k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public v(com.onetrust.otpublishers.headless.UI.fragment.q qVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = qVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objT = this.k.t(0L, null, null, this);
        return objT == kotlin.coroutines.intrinsics.a.a ? objT : new kotlin.r(objT);
    }
}
