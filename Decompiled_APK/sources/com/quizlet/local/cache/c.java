package com.quizlet.local.cache;

import androidx.compose.animation.C0297y;
import kotlin.coroutines.h;

/* loaded from: classes3.dex */
public final class c extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public int k;
    public final /* synthetic */ C0297y l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(C0297y c0297y, h hVar) {
        super(hVar);
        this.l = c0297y;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.k |= Integer.MIN_VALUE;
        return this.l.emit(null, this);
    }
}
