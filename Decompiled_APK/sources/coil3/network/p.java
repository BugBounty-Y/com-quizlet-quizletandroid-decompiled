package coil3.network;

/* loaded from: classes.dex */
public final class p extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public Object k;
    public Object l;
    public /* synthetic */ Object m;
    public final /* synthetic */ q n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public p(q qVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = qVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return q.c(this.n, null, null, null, this);
    }
}
