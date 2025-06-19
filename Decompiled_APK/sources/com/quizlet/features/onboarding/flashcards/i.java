package com.quizlet.features.onboarding.flashcards;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.c {
    public androidx.work.impl.model.e j;
    public androidx.work.impl.model.c k;
    public com.google.mlkit.vision.documentscanner.internal.c l;
    public /* synthetic */ Object m;
    public final /* synthetic */ androidx.work.impl.model.e n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(androidx.work.impl.model.e eVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.i(null, this);
    }
}
