package com.quizlet.remote.model.term;

import com.quizlet.data.repository.classfolder.e;
import kotlin.coroutines.jvm.internal.c;
import kotlin.r;

/* loaded from: classes3.dex */
public final class b extends c {
    public e j;
    public /* synthetic */ Object k;
    public final /* synthetic */ e l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(e eVar, c cVar) {
        super(cVar);
        this.l = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        Object objJ = this.l.j(0L, null, this);
        return objJ == kotlin.coroutines.intrinsics.a.a ? objJ : new r(objJ);
    }
}
