package com.quizlet.data.interactor.folderstudymaterial;

/* loaded from: classes2.dex */
public final class s extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.onetrust.otpublishers.headless.UI.fragment.q k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public s(com.onetrust.otpublishers.headless.UI.fragment.q qVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = qVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objA = this.k.a(0L, null, null, this);
        return objA == kotlin.coroutines.intrinsics.a.a ? objA : new kotlin.r(objA);
    }
}
