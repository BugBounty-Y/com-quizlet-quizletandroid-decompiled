package com.quizlet.data.interactor.universaluploadflow;

import java.util.Iterator;
import java.util.List;

/* loaded from: classes2.dex */
public final class a extends kotlin.coroutines.jvm.internal.c {
    public b j;
    public List k;
    public Iterator l;
    public boolean m;
    public int n;
    public /* synthetic */ Object o;
    public final /* synthetic */ b p;
    public int q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(b bVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.p = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.o = obj;
        this.q |= Integer.MIN_VALUE;
        return this.p.a(null, false, this);
    }
}
