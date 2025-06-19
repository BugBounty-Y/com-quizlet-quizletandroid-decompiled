package com.quizlet.features.folders.addtofolder.viewmodel;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.c {
    public m j;
    public /* synthetic */ Object k;
    public final /* synthetic */ m l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(m mVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = mVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.G(this);
    }
}
