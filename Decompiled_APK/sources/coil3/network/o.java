package coil3.network;

import okio.C5091h;

/* loaded from: classes.dex */
public final class o extends kotlin.coroutines.jvm.internal.c {
    public q j;
    public C5091h k;
    public /* synthetic */ Object l;
    public final /* synthetic */ q m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o(q qVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = qVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return q.b(this.m, null, this);
    }
}
