package com.quizlet.background.metering;

import kotlin.coroutines.jvm.internal.c;

/* loaded from: classes2.dex */
public final class a extends c {
    public /* synthetic */ Object j;
    public final /* synthetic */ MeteringSyncWorker k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(MeteringSyncWorker meteringSyncWorker, c cVar) {
        super(cVar);
        this.k = meteringSyncWorker;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.a(this);
    }
}
