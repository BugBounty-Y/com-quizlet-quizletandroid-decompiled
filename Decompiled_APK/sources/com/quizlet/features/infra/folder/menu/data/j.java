package com.quizlet.features.infra.folder.menu.data;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.c {
    public androidx.compose.material.ripple.r j;
    public /* synthetic */ Object k;
    public final /* synthetic */ androidx.compose.material.ripple.r l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(androidx.compose.material.ripple.r rVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = rVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        Object objF = this.l.f(null, null, this);
        return objF == kotlin.coroutines.intrinsics.a.a ? objF : new kotlin.r(objF);
    }
}
