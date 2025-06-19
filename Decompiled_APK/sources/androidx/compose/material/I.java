package androidx.compose.material;

/* loaded from: classes.dex */
public final class I extends kotlin.coroutines.jvm.internal.c {
    public long j;
    public /* synthetic */ Object k;
    public final /* synthetic */ K l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public I(K k, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = k;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.p(0L, 0L, this);
    }
}
