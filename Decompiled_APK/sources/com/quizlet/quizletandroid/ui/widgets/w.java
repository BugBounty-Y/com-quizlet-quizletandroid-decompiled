package com.quizlet.quizletandroid.ui.widgets;

/* loaded from: classes3.dex */
public final class w extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.quizletandroid.u j;
    public /* synthetic */ Object k;
    public final /* synthetic */ y l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w(y yVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = yVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        this.l.b(null, this);
        return kotlin.coroutines.intrinsics.a.a;
    }
}
