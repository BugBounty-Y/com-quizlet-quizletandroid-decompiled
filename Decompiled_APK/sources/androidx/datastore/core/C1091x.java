package androidx.datastore.core;

/* renamed from: androidx.datastore.core.x, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1091x extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public P k;
    public kotlinx.coroutines.r l;
    public /* synthetic */ Object m;
    public final /* synthetic */ P n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1091x(P p, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return P.c(this.n, null, this);
    }
}
