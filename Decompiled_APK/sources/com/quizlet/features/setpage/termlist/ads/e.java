package com.quizlet.features.setpage.termlist.ads;

import androidx.work.impl.model.i;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.c {
    public i j;
    public List k;
    public Iterator l;
    public /* synthetic */ Object m;
    public final /* synthetic */ i n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(i iVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.g(this);
    }
}
