package com.quizlet.data.repository.foldertoadd;

import com.google.firebase.crashlytics.internal.common.j;
import kotlin.coroutines.jvm.internal.c;
import kotlin.r;

/* loaded from: classes2.dex */
public final class a extends c {
    public /* synthetic */ Object j;
    public final /* synthetic */ j k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(j jVar, c cVar) {
        super(cVar);
        this.k = jVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objC = this.k.c(null, null, null, this);
        return objC == kotlin.coroutines.intrinsics.a.a ? objC : new r(objC);
    }
}
