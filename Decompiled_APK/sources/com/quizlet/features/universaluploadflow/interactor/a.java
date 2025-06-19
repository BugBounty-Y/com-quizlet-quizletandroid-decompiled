package com.quizlet.features.universaluploadflow.interactor;

import androidx.compose.foundation.gestures.l1;
import kotlin.coroutines.jvm.internal.c;

/* loaded from: classes3.dex */
public final class a extends c {
    public l1 j;
    public /* synthetic */ Object k;
    public final /* synthetic */ l1 l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(l1 l1Var, c cVar) {
        super(cVar);
        this.l = l1Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.z(null, this);
    }
}
