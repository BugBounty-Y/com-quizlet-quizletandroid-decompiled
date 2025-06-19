package com.quizlet.data.interactor.report;

import kotlin.coroutines.jvm.internal.c;
import kotlin.r;

/* loaded from: classes2.dex */
public final class a extends c {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.quizlet.data.interactor.course.a k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(com.quizlet.data.interactor.course.a aVar, c cVar) {
        super(cVar);
        this.k = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objI = this.k.i(0, null, null, this);
        return objI == kotlin.coroutines.intrinsics.a.a ? objI : new r(objI);
    }
}
