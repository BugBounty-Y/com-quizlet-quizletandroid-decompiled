package com.quizlet.data.interactor.achievements;

import com.onetrust.otpublishers.headless.UI.fragment.q;

/* loaded from: classes2.dex */
public final class h extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ q k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(q qVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = qVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.u(this);
    }
}
