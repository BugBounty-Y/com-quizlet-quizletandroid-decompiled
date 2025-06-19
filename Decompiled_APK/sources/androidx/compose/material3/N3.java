package androidx.compose.material3;

/* loaded from: classes.dex */
public final class N3 extends kotlin.coroutines.jvm.internal.c {
    public O3 j;
    public V3 k;
    public kotlinx.coroutines.sync.a l;
    public /* synthetic */ Object m;
    public final /* synthetic */ O3 n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public N3(O3 o3, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = o3;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return this.n.a(null, this);
    }
}
