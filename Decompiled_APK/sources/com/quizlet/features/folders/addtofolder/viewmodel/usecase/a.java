package com.quizlet.features.folders.addtofolder.viewmodel.usecase;

import androidx.compose.foundation.gestures.l1;
import java.util.List;

/* loaded from: classes3.dex */
public final class a extends kotlin.coroutines.jvm.internal.c {
    public l1 j;
    public List k;
    public /* synthetic */ Object l;
    public final /* synthetic */ l1 m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(l1 l1Var, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = l1Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.A(null, this);
    }
}
