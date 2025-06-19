package com.quizlet.quizletandroid.managers.deeplinks;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.c {
    public l j;
    public /* synthetic */ Object k;
    public final /* synthetic */ l l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(l lVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = lVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.a(null, this);
    }
}
