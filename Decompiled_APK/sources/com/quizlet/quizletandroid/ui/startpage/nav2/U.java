package com.quizlet.quizletandroid.ui.startpage.nav2;

/* loaded from: classes3.dex */
public final class U extends kotlin.coroutines.jvm.internal.c {
    public Y j;
    public /* synthetic */ Object k;
    public final /* synthetic */ Y l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public U(Y y, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = y;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return Y.B(this.l, this);
    }
}
