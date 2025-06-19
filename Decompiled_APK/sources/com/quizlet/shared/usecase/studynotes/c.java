package com.quizlet.shared.usecase.studynotes;

/* loaded from: classes3.dex */
public final class c extends kotlin.coroutines.jvm.internal.c {
    public d j;
    public /* synthetic */ Object k;
    public final /* synthetic */ d l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(d dVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.a(null, null, this, false);
    }
}
