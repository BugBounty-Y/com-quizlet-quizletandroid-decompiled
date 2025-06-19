package com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel;

/* loaded from: classes3.dex */
public final class o extends kotlin.coroutines.jvm.internal.c {
    public s j;
    public /* synthetic */ Object k;
    public final /* synthetic */ s l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o(s sVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = sVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return s.c(this.l, 0L, this);
    }
}
