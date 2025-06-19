package com.quizlet.shared.cache;

import java.util.Iterator;

/* loaded from: classes3.dex */
public final class v extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.shared.repository.folderstudymaterials.a j;
    public Iterator k;
    public /* synthetic */ Object l;
    public final /* synthetic */ com.quizlet.shared.repository.folderstudymaterials.a m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public v(com.quizlet.shared.repository.folderstudymaterials.a aVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return com.quizlet.shared.repository.folderstudymaterials.a.d(this.m, this);
    }
}
