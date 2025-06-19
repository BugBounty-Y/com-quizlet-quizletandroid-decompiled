package com.quizlet.remote.model.achievements;

import com.google.android.gms.internal.appset.e;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.c {
    public Function0 j;
    public Function1 k;
    public /* synthetic */ Object l;
    public final /* synthetic */ e m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(e eVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.p(null, null, null, null, this);
    }
}
