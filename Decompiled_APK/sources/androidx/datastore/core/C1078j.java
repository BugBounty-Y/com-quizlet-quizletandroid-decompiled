package androidx.datastore.core;

/* renamed from: androidx.datastore.core.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1078j extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public Object k;
    public Object l;
    public kotlin.jvm.internal.J m;
    public P n;
    public /* synthetic */ Object o;
    public final /* synthetic */ C1079k p;
    public int q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1078j(C1079k c1079k, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.p = c1079k;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.o = obj;
        this.q |= Integer.MIN_VALUE;
        return this.p.a(null, this);
    }
}
