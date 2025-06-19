package com.quizlet.features.flashcards;

import com.quizlet.data.model.InterfaceC4176w0;

/* loaded from: classes2.dex */
public final class A extends kotlin.coroutines.jvm.internal.c {
    public S j;
    public InterfaceC4176w0 k;
    public /* synthetic */ Object l;
    public final /* synthetic */ S m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A(S s, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = s;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return S.E(this.m, this);
    }
}
