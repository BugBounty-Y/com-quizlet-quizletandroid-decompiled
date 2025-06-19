package androidx.compose.material3.pulltorefresh;

/* loaded from: classes.dex */
public final class i extends kotlin.coroutines.jvm.internal.c {
    public o j;
    public /* synthetic */ Object k;
    public final /* synthetic */ o l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(o oVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = oVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.Q0(this);
    }
}
