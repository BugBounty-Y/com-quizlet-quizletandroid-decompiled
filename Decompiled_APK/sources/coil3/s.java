package coil3;

/* loaded from: classes.dex */
public final class s extends kotlin.coroutines.jvm.internal.c {
    public u j;
    public coil3.request.n k;
    public coil3.request.g l;
    public f m;
    public j n;
    public /* synthetic */ Object o;
    public final /* synthetic */ u p;
    public int q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public s(u uVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.p = uVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.o = obj;
        this.q |= Integer.MIN_VALUE;
        return this.p.a(null, 0, this);
    }
}
