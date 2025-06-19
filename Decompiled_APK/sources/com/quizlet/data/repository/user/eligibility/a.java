package com.quizlet.data.repository.user.eligibility;

/* loaded from: classes2.dex */
public final class a extends kotlin.coroutines.jvm.internal.c {
    public g j;
    public /* synthetic */ Object k;
    public final /* synthetic */ g l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(g gVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.a(this);
    }
}
