package com.quizlet.quizletandroid.ui;

import androidx.camera.camera2.internal.c0;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.c {
    public c0 j;
    public /* synthetic */ Object k;
    public final /* synthetic */ c0 l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(c0 c0Var, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = c0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.k(this);
    }
}
