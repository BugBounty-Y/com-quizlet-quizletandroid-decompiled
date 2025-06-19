package com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel;

/* loaded from: classes3.dex */
public final class B extends kotlin.coroutines.jvm.internal.c {
    public boolean j;
    public /* synthetic */ Object k;
    public final /* synthetic */ G l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B(G g, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = g;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.c(false, this);
    }
}
