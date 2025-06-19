package androidx.paging;

/* loaded from: classes.dex */
public final class U extends kotlin.coroutines.jvm.internal.c {
    public V j;
    public S0 k;
    public /* synthetic */ Object l;
    public final /* synthetic */ V m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public U(V v, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = v;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return V.a(this.m, null, this);
    }
}
