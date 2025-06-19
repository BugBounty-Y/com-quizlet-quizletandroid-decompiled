package com.features.flashcards.creatormarketing;

/* loaded from: classes2.dex */
public final class m extends kotlin.coroutines.jvm.internal.c {
    public o j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ o m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(o oVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = oVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.c(this);
    }
}
