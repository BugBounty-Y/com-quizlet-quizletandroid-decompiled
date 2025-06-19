package androidx.datastore.core;

import java.io.Serializable;

/* loaded from: classes.dex */
public final class E extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public Object k;
    public Serializable l;
    public kotlin.jvm.internal.J m;
    public boolean n;
    public int o;
    public /* synthetic */ Object p;
    public final /* synthetic */ P q;
    public int r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E(P p, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.q = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.p = obj;
        this.r |= Integer.MIN_VALUE;
        return P.f(this.q, false, this);
    }
}
