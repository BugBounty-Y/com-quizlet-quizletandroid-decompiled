package com.quizlet.features.infra.google;

import java.io.Serializable;
import kotlin.r;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.c {
    public e j;
    public e k;
    public boolean l;
    public /* synthetic */ Object m;
    public final /* synthetic */ e n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(e eVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        Serializable serializableD = this.n.d(null, false, this);
        return serializableD == kotlin.coroutines.intrinsics.a.a ? serializableD : new r(serializableD);
    }
}
