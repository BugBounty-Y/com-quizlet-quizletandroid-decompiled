package com.quizlet.data.interactor.freetrial;

import androidx.work.impl.model.e;
import kotlin.coroutines.jvm.internal.c;

/* loaded from: classes2.dex */
public final class b extends c {
    public e j;
    public /* synthetic */ Object k;
    public final /* synthetic */ e l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(e eVar, c cVar) {
        super(cVar);
        this.l = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.v(this);
    }
}
