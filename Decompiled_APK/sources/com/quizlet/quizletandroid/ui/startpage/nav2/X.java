package com.quizlet.quizletandroid.ui.startpage.nav2;

import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class X extends kotlin.coroutines.jvm.internal.c {
    public Y j;
    public s0 k;
    public Object l;
    public /* synthetic */ Object m;
    public final /* synthetic */ Y n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public X(Y y, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = y;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return Y.C(this.n, null, this);
    }
}
