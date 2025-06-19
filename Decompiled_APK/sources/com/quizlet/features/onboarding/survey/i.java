package com.quizlet.features.onboarding.survey;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public androidx.work.impl.model.c k;
    public /* synthetic */ Object l;
    public final /* synthetic */ j m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(j jVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = jVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.a(null, this);
    }
}
