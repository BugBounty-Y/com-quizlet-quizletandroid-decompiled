package androidx.compose.foundation;

/* renamed from: androidx.compose.foundation.k, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0370k extends kotlin.coroutines.jvm.internal.c {
    public C0456n j;
    public long k;
    public /* synthetic */ Object l;
    public final /* synthetic */ C0456n m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0370k(C0456n c0456n, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = c0456n;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.b(0L, null, this);
    }
}
