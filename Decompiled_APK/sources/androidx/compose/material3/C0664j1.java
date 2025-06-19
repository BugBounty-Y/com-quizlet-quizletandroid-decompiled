package androidx.compose.material3;

/* renamed from: androidx.compose.material3.j1, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0664j1 extends kotlin.coroutines.jvm.internal.c {
    public C0670k1 j;
    public long k;
    public /* synthetic */ Object l;
    public final /* synthetic */ C0670k1 m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0664j1(C0670k1 c0670k1, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = c0670k1;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.p(0L, 0L, this);
    }
}
