package com.quizlet.login.common.interactors;

import com.quizlet.db.data.models.persisted.DBUser;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.c {
    public androidx.compose.runtime.internal.j j;
    public DBUser k;
    public String l;
    public boolean m;
    public int n;
    public /* synthetic */ Object o;
    public final /* synthetic */ androidx.compose.runtime.internal.j p;
    public int q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(androidx.compose.runtime.internal.j jVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.p = jVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.o = obj;
        this.q |= Integer.MIN_VALUE;
        return this.p.q(null, null, false, null, this);
    }
}
