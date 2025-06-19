package com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel;

/* loaded from: classes3.dex */
public final class C extends kotlin.coroutines.jvm.internal.c {
    public G j;
    public long k;
    public /* synthetic */ Object l;
    public final /* synthetic */ G m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C(G g, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = g;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.d(0L, null, this);
    }
}
