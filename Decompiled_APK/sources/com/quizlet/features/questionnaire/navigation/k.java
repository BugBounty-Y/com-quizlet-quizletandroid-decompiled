package com.quizlet.features.questionnaire.navigation;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.c {
    public m j;
    public String k;
    public /* synthetic */ Object l;
    public final /* synthetic */ m m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(m mVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return m.A(this.m, null, this);
    }
}
