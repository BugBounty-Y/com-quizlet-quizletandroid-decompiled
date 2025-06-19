package com.quizlet.login.common.interactors;

/* loaded from: classes3.dex */
public final class s extends kotlin.coroutines.jvm.internal.c {
    public com.google.firebase.messaging.u j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.google.firebase.messaging.u l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public s(com.google.firebase.messaging.u uVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = uVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.g(null, this);
    }
}
