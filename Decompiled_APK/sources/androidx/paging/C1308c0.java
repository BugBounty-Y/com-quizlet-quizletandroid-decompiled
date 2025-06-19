package androidx.paging;

/* renamed from: androidx.paging.c0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1308c0 extends kotlin.coroutines.jvm.internal.c {
    public C1336q0 j;
    public C1337r0 k;
    public kotlinx.coroutines.sync.c l;
    public /* synthetic */ Object m;
    public final /* synthetic */ C1336q0 n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1308c0(C1336q0 c1336q0, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = c1336q0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.e(this);
    }
}
