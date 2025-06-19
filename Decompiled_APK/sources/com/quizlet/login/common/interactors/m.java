package com.quizlet.login.common.interactors;

/* loaded from: classes3.dex */
public final class m extends kotlin.coroutines.jvm.internal.c {
    public o j;
    public /* synthetic */ Object k;
    public final /* synthetic */ o l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(o oVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = oVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.a(null, this);
    }
}
