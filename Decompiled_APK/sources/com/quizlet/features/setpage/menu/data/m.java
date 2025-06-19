package com.quizlet.features.setpage.menu.data;

import com.quizlet.data.model.A0;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final class m extends kotlin.coroutines.jvm.internal.c {
    public A0 j;
    public Function0 k;
    public com.quizlet.features.setpage.data.b l;
    public int m;
    public /* synthetic */ Object n;
    public final /* synthetic */ com.google.android.material.floatingactionbutton.c o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(com.google.android.material.floatingactionbutton.c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        super(cVar2);
        this.o = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return this.o.c(null, null, this);
    }
}
