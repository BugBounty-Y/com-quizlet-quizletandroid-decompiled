package com.quizlet.quizletandroid.ui.common.ads;

/* loaded from: classes3.dex */
public final class l extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ E k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(E e, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = e;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objA = E.a(this.k, 0, null, this);
        return objA == kotlin.coroutines.intrinsics.a.a ? objA : new kotlin.r(objA);
    }
}
