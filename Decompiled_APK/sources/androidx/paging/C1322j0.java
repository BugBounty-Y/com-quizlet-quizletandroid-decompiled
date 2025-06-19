package androidx.paging;

/* renamed from: androidx.paging.j0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1322j0 extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public Object k;
    public Object l;
    public Object m;
    public Object n;
    public Object o;
    public Object p;
    public C1336q0 q;
    public /* synthetic */ Object r;
    public final /* synthetic */ C1324k0 s;
    public int t;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1322j0(C1324k0 c1324k0, kotlin.coroutines.h hVar) {
        super(hVar);
        this.s = c1324k0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.r = obj;
        this.t |= Integer.MIN_VALUE;
        return this.s.a(this);
    }
}
