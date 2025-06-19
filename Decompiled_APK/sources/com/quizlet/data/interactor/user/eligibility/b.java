package com.quizlet.data.interactor.user.eligibility;

import com.quizlet.generated.enums.I0;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.c;

/* loaded from: classes2.dex */
public final class b extends c {
    public I0 j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.quizlet.data.repository.activitycenter.b l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(com.quizlet.data.repository.activitycenter.b bVar, h hVar) {
        super(hVar);
        this.l = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.j(null, this);
    }
}
