package com.quizlet.data.interactor.foldertoadd;

import com.google.firebase.messaging.p;
import kotlin.coroutines.jvm.internal.c;
import kotlin.r;

/* loaded from: classes2.dex */
public final class a extends c {
    public /* synthetic */ Object j;
    public final /* synthetic */ p k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(p pVar, c cVar) {
        super(cVar);
        this.k = pVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objW = this.k.w(null, null, null, this);
        return objW == kotlin.coroutines.intrinsics.a.a ? objW : new r(objW);
    }
}
