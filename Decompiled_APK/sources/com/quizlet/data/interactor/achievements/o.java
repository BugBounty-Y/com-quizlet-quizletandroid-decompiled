package com.quizlet.data.interactor.achievements;

/* loaded from: classes2.dex */
public final class o extends kotlin.coroutines.jvm.internal.c {
    public com.google.android.material.floatingactionbutton.c j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.google.android.material.floatingactionbutton.c l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o(com.google.android.material.floatingactionbutton.c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        super(cVar2);
        this.l = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.n(this);
    }
}
