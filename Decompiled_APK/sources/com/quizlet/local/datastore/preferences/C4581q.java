package com.quizlet.local.datastore.preferences;

import androidx.compose.foundation.gestures.l1;

/* renamed from: com.quizlet.local.datastore.preferences.q, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4581q extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ l1 k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4581q(l1 l1Var, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = l1Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.x(0L, this);
    }
}
