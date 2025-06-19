package kotlinx.coroutines.flow;

/* loaded from: classes3.dex */
public final class u0 extends kotlin.coroutines.jvm.internal.c {
    public v0 j;
    public kotlinx.coroutines.flow.internal.C k;
    public /* synthetic */ Object l;
    public final /* synthetic */ v0 m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u0(v0 v0Var, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = v0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.a(this);
    }
}
