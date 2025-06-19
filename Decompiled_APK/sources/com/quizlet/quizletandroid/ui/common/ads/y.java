package com.quizlet.quizletandroid.ui.common.ads;

import androidx.compose.foundation.K;

/* loaded from: classes3.dex */
public final class y extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public int k;
    public final /* synthetic */ K l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public y(K k, kotlin.coroutines.h hVar) {
        super(hVar);
        this.l = k;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.k |= Integer.MIN_VALUE;
        return this.l.emit(null, this);
    }
}
