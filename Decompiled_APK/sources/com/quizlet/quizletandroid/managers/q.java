package com.quizlet.quizletandroid.managers;

/* loaded from: classes3.dex */
public final class q extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ u k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(u uVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = uVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.b(false, this);
    }
}
