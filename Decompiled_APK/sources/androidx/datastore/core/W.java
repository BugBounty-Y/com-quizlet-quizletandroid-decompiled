package androidx.datastore.core;

/* loaded from: classes.dex */
public final class W extends kotlin.coroutines.jvm.internal.c {
    public X j;
    public Object k;
    public Object l;
    public Z m;
    public /* synthetic */ Object n;
    public final /* synthetic */ X o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public W(X x, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = x;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return this.o.a(null, this);
    }
}
