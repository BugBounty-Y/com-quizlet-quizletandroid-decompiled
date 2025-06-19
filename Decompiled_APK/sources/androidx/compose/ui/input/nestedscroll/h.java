package androidx.compose.ui.input.nestedscroll;

/* loaded from: classes.dex */
public final class h extends kotlin.coroutines.jvm.internal.c {
    public i j;
    public long k;
    public /* synthetic */ Object l;
    public final /* synthetic */ i m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(i iVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.i0(0L, this);
    }
}
