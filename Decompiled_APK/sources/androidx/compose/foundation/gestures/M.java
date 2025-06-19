package androidx.compose.foundation.gestures;

/* loaded from: classes.dex */
public final class M extends kotlin.coroutines.jvm.internal.c {
    public Q j;
    public C0356w k;
    public androidx.compose.foundation.interaction.b l;
    public /* synthetic */ Object m;
    public final /* synthetic */ Q n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public M(Q q, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = q;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return Q.Q0(this.n, null, this);
    }
}
