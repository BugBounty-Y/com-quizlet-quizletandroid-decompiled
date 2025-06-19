package com.quizlet.remote.model.notes;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.jvm.internal.J;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.data.repository.widget.b j;
    public List k;
    public Map l;
    public Collection m;
    public Iterator n;
    public J o;
    public String p;
    public String q;
    public String r;
    public List s;
    public Collection t;
    public int u;
    public /* synthetic */ Object v;
    public final /* synthetic */ com.quizlet.data.repository.widget.b w;
    public int x;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(com.quizlet.data.repository.widget.b bVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.w = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.v = obj;
        this.x |= Integer.MIN_VALUE;
        return this.w.r(null, this);
    }
}
