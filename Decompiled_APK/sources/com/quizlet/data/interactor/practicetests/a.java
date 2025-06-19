package com.quizlet.data.interactor.practicetests;

import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class a extends kotlin.coroutines.jvm.internal.c {
    public ArrayList j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.quizlet.data.repository.activitycenter.b l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(com.quizlet.data.repository.activitycenter.b bVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.k(null, this);
    }
}
