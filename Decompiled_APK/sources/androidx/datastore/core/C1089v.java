package androidx.datastore.core;

/* renamed from: androidx.datastore.core.v, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1089v extends kotlin.coroutines.jvm.internal.c {
    public P j;
    public kotlinx.coroutines.sync.c k;
    public /* synthetic */ Object l;
    public final /* synthetic */ P m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1089v(P p, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return P.b(this.m, this);
    }
}
