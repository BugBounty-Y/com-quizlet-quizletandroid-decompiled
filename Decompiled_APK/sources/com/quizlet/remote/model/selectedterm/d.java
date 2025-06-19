package com.quizlet.remote.model.selectedterm;

import com.quizlet.quizletandroid.k;
import kotlin.r;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.remote.model.base.a j;
    public /* synthetic */ Object k;
    public final /* synthetic */ k l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(k kVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = kVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        Object objL = this.l.l(0L, 0L, null, this);
        return objL == kotlin.coroutines.intrinsics.a.a ? objL : new r(objL);
    }
}
