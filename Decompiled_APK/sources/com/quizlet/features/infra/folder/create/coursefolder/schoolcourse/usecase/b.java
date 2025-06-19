package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.usecase;

import kotlin.r;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.quizlet.data.repository.widget.b k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(com.quizlet.data.repository.widget.b bVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        Object objH = this.k.h(0L, this);
        return objH == kotlin.coroutines.intrinsics.a.a ? objH : new r(objH);
    }
}
