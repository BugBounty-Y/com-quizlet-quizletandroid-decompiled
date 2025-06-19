package com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel;

import com.quizlet.generated.enums.P;

/* loaded from: classes3.dex */
public final class v extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.data.interactor.metering.b j;
    public Long k;
    public P l;
    public long m;
    public /* synthetic */ Object n;
    public final /* synthetic */ y o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public v(y yVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = yVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return y.a(this.o, 0L, null, this);
    }
}
