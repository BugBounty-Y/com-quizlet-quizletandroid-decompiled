package com.quizlet.features.setpage.termlist.ads;

import androidx.work.impl.model.i;
import java.util.Map;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.c {
    public i j;
    public com.quizlet.ads.c k;
    public com.quizlet.ads.helper.b l;
    public Map m;
    public /* synthetic */ Object n;
    public final /* synthetic */ i o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(i iVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return this.o.f(null, this);
    }
}
