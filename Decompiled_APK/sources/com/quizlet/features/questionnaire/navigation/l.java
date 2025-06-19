package com.quizlet.features.questionnaire.navigation;

/* loaded from: classes3.dex */
public final class l extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ m k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(m mVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.C(this);
    }
}
