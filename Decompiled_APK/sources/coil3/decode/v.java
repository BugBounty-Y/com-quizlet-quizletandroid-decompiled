package coil3.decode;

/* loaded from: classes.dex */
public final class v extends kotlin.coroutines.jvm.internal.c {
    public x j;
    public kotlinx.coroutines.sync.i k;
    public /* synthetic */ Object l;
    public final /* synthetic */ x m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public v(x xVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = xVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.a(this);
    }
}
