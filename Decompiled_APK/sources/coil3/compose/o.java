package coil3.compose;

/* loaded from: classes.dex */
public final class o extends kotlin.coroutines.jvm.internal.c {
    public p j;
    public kotlin.coroutines.p k;
    public /* synthetic */ Object l;
    public final /* synthetic */ p m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o(p pVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = pVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.l(this);
    }
}
