package com.quizlet.features.notes.detail.viewmodels;

import com.quizlet.data.model.NotesToValueInfo;
import kotlinx.coroutines.flow.X;

/* loaded from: classes3.dex */
public final class u extends kotlin.coroutines.jvm.internal.c {
    public v j;
    public com.quizlet.features.notes.data.c k;
    public X l;
    public Object m;
    public NotesToValueInfo n;
    public boolean o;
    public int p;
    public /* synthetic */ Object q;
    public final /* synthetic */ v r;
    public int s;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u(v vVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.r = vVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.q = obj;
        this.s |= Integer.MIN_VALUE;
        return this.r.G(null, this);
    }
}
