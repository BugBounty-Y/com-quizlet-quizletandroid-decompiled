package com.quizlet.features.settings.viewmodels;

import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class w extends kotlin.coroutines.jvm.internal.c {
    public I j;
    public s0 k;
    public Object l;
    public com.quizlet.features.settings.data.states.y m;
    public /* synthetic */ Object n;
    public final /* synthetic */ I o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w(I i, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return I.A(this.o, this);
    }
}
