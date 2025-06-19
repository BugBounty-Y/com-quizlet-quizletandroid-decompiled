package com.quizlet.shared.quizletapi.studynotes;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.shared.httpclient.e j;
    public /* synthetic */ Object k;
    public final /* synthetic */ k l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(k kVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = kVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.a(null, this);
    }
}
