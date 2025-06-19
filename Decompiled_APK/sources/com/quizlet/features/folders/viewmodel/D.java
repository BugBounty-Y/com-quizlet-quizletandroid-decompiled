package com.quizlet.features.folders.viewmodel;

import androidx.datastore.core.C1086s;

/* loaded from: classes3.dex */
public final class D extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public int k;
    public final /* synthetic */ C1086s l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D(C1086s c1086s, kotlin.coroutines.h hVar) {
        super(hVar);
        this.l = c1086s;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.k |= Integer.MIN_VALUE;
        return this.l.emit(null, this);
    }
}
