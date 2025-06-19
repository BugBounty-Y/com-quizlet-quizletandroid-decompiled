package com.quizlet.features.setpage.termlist.ads;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.c {
    public io.ktor.client.plugins.api.d j;
    public /* synthetic */ Object k;
    public final /* synthetic */ io.ktor.client.plugins.api.d l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(io.ktor.client.plugins.api.d dVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.v(this);
    }
}
