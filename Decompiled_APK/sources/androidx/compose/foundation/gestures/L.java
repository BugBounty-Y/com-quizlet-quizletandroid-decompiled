package androidx.compose.foundation.gestures;

/* loaded from: classes.dex */
public final class L extends kotlin.coroutines.jvm.internal.c {
    public Q j;
    public /* synthetic */ Object k;
    public final /* synthetic */ Q l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public L(Q q, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = q;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return Q.P0(this.l, this);
    }
}
