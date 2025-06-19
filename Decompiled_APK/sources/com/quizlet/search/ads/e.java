package com.quizlet.search.ads;

import java.util.Iterator;
import java.util.List;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.data.repository.folderwithcreator.e j;
    public List k;
    public Iterator l;
    public /* synthetic */ Object m;
    public final /* synthetic */ com.quizlet.data.repository.folderwithcreator.e n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(com.quizlet.data.repository.folderwithcreator.e eVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.n(0, this);
    }
}
