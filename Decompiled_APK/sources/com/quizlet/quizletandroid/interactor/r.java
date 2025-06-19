package com.quizlet.quizletandroid.interactor;

import androidx.work.impl.model.v;

/* loaded from: classes3.dex */
public final class r extends kotlin.coroutines.jvm.internal.c {
    public v j;
    public /* synthetic */ Object k;
    public final /* synthetic */ v l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(v vVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = vVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.i(this);
    }
}
