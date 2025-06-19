package com.quizlet.search.viewmodels;

import androidx.compose.foundation.text.C0494i0;
import androidx.paging.C1351y0;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes3.dex */
public final class B extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public int k;
    public C0494i0 l;
    public final /* synthetic */ C0494i0 m;
    public InterfaceC5002j n;
    public C1351y0 o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B(C0494i0 c0494i0, kotlin.coroutines.h hVar) {
        super(hVar);
        this.m = c0494i0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.k |= Integer.MIN_VALUE;
        return this.m.emit(null, this);
    }
}
