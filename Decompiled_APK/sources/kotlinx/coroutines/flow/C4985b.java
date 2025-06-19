package kotlinx.coroutines.flow;

/* renamed from: kotlinx.coroutines.flow.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4985b extends kotlin.coroutines.jvm.internal.c {
    public kotlinx.coroutines.channels.u j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C4986c l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4985b(C4986c c4986c, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = c4986c;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.e(null, this);
    }
}
