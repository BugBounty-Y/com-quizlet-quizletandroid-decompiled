package com.quizlet.search.ads;

import java.util.Map;

/* loaded from: classes3.dex */
public final class c extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.data.repository.folderwithcreator.e j;
    public com.quizlet.ads.c k;
    public com.quizlet.ads.helper.b l;
    public Map m;
    public /* synthetic */ Object n;
    public final /* synthetic */ com.quizlet.data.repository.folderwithcreator.e o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(com.quizlet.data.repository.folderwithcreator.e eVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return this.o.m(null, this);
    }
}
