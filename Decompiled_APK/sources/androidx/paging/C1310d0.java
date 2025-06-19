package androidx.paging;

/* renamed from: androidx.paging.d0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1310d0 extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public Object k;
    public Object l;
    public kotlinx.coroutines.sync.c m;
    public /* synthetic */ Object n;
    public final /* synthetic */ C1336q0 o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1310d0(C1336q0 c1336q0, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = c1336q0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return this.o.f(this);
    }
}
