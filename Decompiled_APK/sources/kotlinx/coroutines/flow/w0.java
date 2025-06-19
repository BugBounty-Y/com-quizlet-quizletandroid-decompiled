package kotlinx.coroutines.flow;

/* loaded from: classes3.dex */
public final class w0 extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ x0 k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w0(x0 x0Var, kotlin.coroutines.h hVar) {
        super(hVar);
        this.k = x0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        this.k.b(null, this);
        return kotlin.coroutines.intrinsics.a.a;
    }
}
