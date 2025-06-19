package com.quizlet.local.datastore.preferences;

/* loaded from: classes3.dex */
public final class x0 extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.quizlet.local.datastore.models.metering.i k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public x0(com.quizlet.local.datastore.models.metering.i iVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.b(this);
    }
}
