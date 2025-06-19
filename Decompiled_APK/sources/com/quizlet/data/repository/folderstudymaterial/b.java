package com.quizlet.data.repository.folderstudymaterial;

import com.google.firebase.messaging.p;
import kotlin.coroutines.jvm.internal.c;
import kotlin.r;

/* loaded from: classes2.dex */
public final class b extends c {
    public /* synthetic */ Object j;
    public final /* synthetic */ p k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(p pVar, c cVar) {
        super(cVar);
        this.k = pVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objG = this.k.g(null, this);
        return objG == kotlin.coroutines.intrinsics.a.a ? objG : new r(objG);
    }
}
