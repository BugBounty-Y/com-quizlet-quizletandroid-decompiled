package com.google.firebase.sessions.api;

import java.util.Iterator;
import java.util.Map;

/* loaded from: classes2.dex */
public final class b extends kotlin.coroutines.jvm.internal.c {
    public Map j;
    public Iterator k;
    public d l;
    public kotlinx.coroutines.sync.a m;
    public Map n;
    public Object o;
    public /* synthetic */ Object p;
    public final /* synthetic */ c q;
    public int r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        super(cVar2);
        this.q = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.p = obj;
        this.r |= Integer.MIN_VALUE;
        return this.q.b(this);
    }
}
