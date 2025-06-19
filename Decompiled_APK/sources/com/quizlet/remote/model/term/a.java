package com.quizlet.remote.model.term;

import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import kotlin.coroutines.jvm.internal.c;
import kotlin.r;

/* loaded from: classes3.dex */
public final class a extends c {
    public com.quizlet.remote.model.base.a j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C4636c l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(C4636c c4636c, c cVar) {
        super(cVar);
        this.l = c4636c;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        Object objC = this.l.c(0L, null, this);
        return objC == kotlin.coroutines.intrinsics.a.a ? objC : new r(objC);
    }
}
