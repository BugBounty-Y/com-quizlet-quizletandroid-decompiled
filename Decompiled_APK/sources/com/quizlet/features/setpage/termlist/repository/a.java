package com.quizlet.features.setpage.termlist.repository;

import kotlin.coroutines.jvm.internal.c;

/* loaded from: classes3.dex */
public final class a extends c {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.google.mlkit.vision.documentscanner.internal.c k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(com.google.mlkit.vision.documentscanner.internal.c cVar, c cVar2) {
        super(cVar2);
        this.k = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.k(0L, this);
    }
}
