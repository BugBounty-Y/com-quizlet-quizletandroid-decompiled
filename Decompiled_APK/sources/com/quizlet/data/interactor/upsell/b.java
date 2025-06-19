package com.quizlet.data.interactor.upsell;

import androidx.work.impl.model.v;
import kotlin.coroutines.jvm.internal.c;

/* loaded from: classes2.dex */
public final class b extends c {
    public v j;
    public boolean k;
    public /* synthetic */ Object l;
    public final /* synthetic */ v m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(v vVar, c cVar) {
        super(cVar);
        this.m = vVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.l(this);
    }
}
