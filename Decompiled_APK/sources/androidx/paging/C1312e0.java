package androidx.paging;

/* renamed from: androidx.paging.e0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1312e0 extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public Object k;
    public Object l;
    public Object m;
    public Object n;
    public Object o;
    public Object p;
    public Object q;
    public Object r;
    public Object s;
    public kotlinx.coroutines.sync.c t;
    public /* synthetic */ Object u;
    public final /* synthetic */ C1336q0 v;
    public int w;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1312e0(C1336q0 c1336q0, kotlin.coroutines.h hVar) {
        super(hVar);
        this.v = c1336q0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.u = obj;
        this.w |= Integer.MIN_VALUE;
        return C1336q0.b(this.v, null, null, this);
    }
}
