package com.mayakapps.kache;

import java.util.Iterator;
import java.util.LinkedHashMap;

/* loaded from: classes2.dex */
public final class z extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public okio.x k;
    public x l;
    public kotlinx.coroutines.C m;
    public y n;
    public com.mayakapps.kache.journal.a o;
    public Iterator p;
    public String q;
    public LinkedHashMap r;
    public long s;
    public /* synthetic */ Object t;
    public final /* synthetic */ com.quizlet.shared.usecase.folderstudymaterials.d u;
    public int v;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public z(com.quizlet.shared.usecase.folderstudymaterials.d dVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.u = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.t = obj;
        this.v |= Integer.MIN_VALUE;
        return this.u.m(null, null, 0L, null, null, 0, null, this);
    }
}
