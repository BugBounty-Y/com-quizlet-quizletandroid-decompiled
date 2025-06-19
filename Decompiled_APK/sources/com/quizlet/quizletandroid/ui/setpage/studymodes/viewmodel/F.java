package com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel;

import com.quizlet.data.model.A0;
import com.quizlet.data.model.InterfaceC4156p0;

/* loaded from: classes3.dex */
public final class F extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public A0 k;
    public Object l;
    public InterfaceC4156p0 m;
    public long n;
    public boolean o;
    public /* synthetic */ Object p;
    public final /* synthetic */ G q;
    public int r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public F(G g, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.q = g;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.p = obj;
        this.r |= Integer.MIN_VALUE;
        return G.a(this.q, 0L, false, false, this);
    }
}
