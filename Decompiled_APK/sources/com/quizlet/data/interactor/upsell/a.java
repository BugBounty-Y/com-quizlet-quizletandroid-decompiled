package com.quizlet.data.interactor.upsell;

import androidx.work.impl.model.v;
import kotlin.coroutines.jvm.internal.c;

/* loaded from: classes2.dex */
public final class a extends c {
    public v j;
    public /* synthetic */ Object k;
    public final /* synthetic */ v l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(v vVar, c cVar) {
        super(cVar);
        this.l = vVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.j(this);
    }
}
