package com.quizlet.local.datastore.models.metering;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public int k;
    public final /* synthetic */ com.perimeterx.mobile_sdk.local_data.h l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(com.perimeterx.mobile_sdk.local_data.h hVar, kotlin.coroutines.h hVar2) {
        super(hVar2);
        this.l = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.k |= Integer.MIN_VALUE;
        return this.l.emit(null, this);
    }
}
