package com.quizlet.data.interactor.user.delete;

import com.onetrust.otpublishers.headless.UI.fragment.q;
import kotlin.coroutines.jvm.internal.c;
import kotlin.r;

/* loaded from: classes2.dex */
public final class a extends c {
    public /* synthetic */ Object j;
    public final /* synthetic */ q k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(q qVar, c cVar) {
        super(cVar);
        this.k = qVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objO = this.k.o(this);
        return objO == kotlin.coroutines.intrinsics.a.a ? objO : new r(objO);
    }
}
