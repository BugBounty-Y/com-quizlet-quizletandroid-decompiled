package com.quizlet.features.setpage.usecases;

import com.quizlet.data.model.Z1;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.c {
    public androidx.compose.runtime.internal.j j;
    public Z1 k;
    public com.quizlet.infra.legacysyncengine.features.properties.d l;
    public long m;
    public boolean n;
    public boolean o;
    public boolean p;
    public boolean q;
    public boolean r;
    public boolean s;
    public boolean t;
    public boolean u;
    public /* synthetic */ Object v;
    public final /* synthetic */ androidx.compose.runtime.internal.j w;
    public int x;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(androidx.compose.runtime.internal.j jVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.w = jVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.v = obj;
        this.x |= Integer.MIN_VALUE;
        return this.w.r(0L, this);
    }
}
