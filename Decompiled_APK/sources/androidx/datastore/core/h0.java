package androidx.datastore.core;

/* loaded from: classes.dex */
public final class h0 extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public kotlinx.coroutines.sync.c k;
    public /* synthetic */ Object l;
    public final /* synthetic */ k0 m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h0(k0 k0Var, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = k0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.b(null, this);
    }
}
