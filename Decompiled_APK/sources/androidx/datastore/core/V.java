package androidx.datastore.core;

/* loaded from: classes.dex */
public final class V extends kotlin.coroutines.jvm.internal.c {
    public X j;
    public S k;
    public boolean l;
    public /* synthetic */ Object m;
    public final /* synthetic */ X n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public V(X x, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = x;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.d(null, this);
    }
}
