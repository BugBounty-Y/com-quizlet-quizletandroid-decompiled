package com.quizlet.features.setpage.menu.data;

import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final class n extends kotlin.coroutines.jvm.internal.c {
    public Function0 j;
    public com.quizlet.features.setpage.data.b k;
    public int l;
    public /* synthetic */ Object m;
    public final /* synthetic */ com.google.android.material.floatingactionbutton.c n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(com.google.android.material.floatingactionbutton.c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        super(cVar2);
        this.n = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.d(null, this);
    }
}
