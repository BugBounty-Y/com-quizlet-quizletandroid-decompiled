package com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel;

/* loaded from: classes3.dex */
public final class A extends kotlin.coroutines.jvm.internal.c {
    public boolean j;
    public /* synthetic */ Object k;
    public final /* synthetic */ G l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A(G g, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = g;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.b(false, this);
    }
}
