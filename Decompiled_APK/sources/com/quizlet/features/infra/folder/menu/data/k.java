package com.quizlet.features.infra.folder.menu.data;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.c {
    public androidx.compose.material.ripple.r j;
    public long k;
    public /* synthetic */ Object l;
    public final /* synthetic */ androidx.compose.material.ripple.r m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(androidx.compose.material.ripple.r rVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = rVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        Object objG = this.m.g(0L, null, null, this);
        return objG == kotlin.coroutines.intrinsics.a.a ? objG : new kotlin.r(objG);
    }
}
