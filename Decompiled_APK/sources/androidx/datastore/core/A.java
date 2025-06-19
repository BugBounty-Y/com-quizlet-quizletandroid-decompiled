package androidx.datastore.core;

/* loaded from: classes.dex */
public final class A extends kotlin.coroutines.jvm.internal.c {
    public P j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ P m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A(P p, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.h(this);
    }
}
