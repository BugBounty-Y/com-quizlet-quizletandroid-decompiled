package androidx.compose.foundation.gestures;

/* loaded from: classes.dex */
public final class N extends kotlin.coroutines.jvm.internal.c {
    public Q j;
    public C0358x k;
    public /* synthetic */ Object l;
    public final /* synthetic */ Q m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public N(Q q, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = q;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return Q.R0(this.m, null, this);
    }
}
