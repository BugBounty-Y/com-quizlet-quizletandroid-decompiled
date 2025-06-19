package com.quizlet.features.settings.viewmodels;

/* loaded from: classes3.dex */
public final class x extends kotlin.coroutines.jvm.internal.c {
    public I j;
    public /* synthetic */ Object k;
    public final /* synthetic */ I l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public x(I i, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return I.B(this.l, 0, this);
    }
}
