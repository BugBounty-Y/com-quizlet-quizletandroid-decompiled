package androidx.compose.material3.pulltorefresh;

/* loaded from: classes.dex */
public final class l extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ o k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(o oVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = oVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.i0(0L, this);
    }
}
