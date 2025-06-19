package com.quizlet.features.flashcards;

/* loaded from: classes2.dex */
public final class w extends kotlin.coroutines.jvm.internal.c {
    public S j;
    public /* synthetic */ Object k;
    public final /* synthetic */ S l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w(S s, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = s;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return S.B(this.l, null, this);
    }
}
