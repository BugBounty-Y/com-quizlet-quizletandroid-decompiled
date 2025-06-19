package androidx.datastore.core;

/* loaded from: classes.dex */
public final class B extends kotlin.coroutines.jvm.internal.c {
    public P j;
    public l0 k;
    public boolean l;
    public /* synthetic */ Object m;
    public final /* synthetic */ P n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B(P p, kotlin.coroutines.h hVar) {
        super(hVar);
        this.n = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return P.e(this.n, false, this);
    }
}
