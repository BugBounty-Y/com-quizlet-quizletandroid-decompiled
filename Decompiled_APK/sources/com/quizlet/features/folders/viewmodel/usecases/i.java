package com.quizlet.features.folders.viewmodel.usecases;

import java.io.Serializable;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.c {
    public io.ktor.client.plugins.api.d j;
    public long k;
    public /* synthetic */ Object l;
    public final /* synthetic */ io.ktor.client.plugins.api.d m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(io.ktor.client.plugins.api.d dVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        Serializable serializableT = this.m.t(0L, this);
        return serializableT == kotlin.coroutines.intrinsics.a.a ? serializableT : new kotlin.r(serializableT);
    }
}
