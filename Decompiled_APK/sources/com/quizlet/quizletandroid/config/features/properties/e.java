package com.quizlet.quizletandroid.config.features.properties;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ androidx.work.impl.model.c k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(androidx.work.impl.model.c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        super(cVar2);
        this.k = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.d(this);
    }
}
