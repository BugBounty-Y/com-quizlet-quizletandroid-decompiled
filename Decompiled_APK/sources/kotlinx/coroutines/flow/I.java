package kotlinx.coroutines.flow;

/* loaded from: classes3.dex */
public final class I extends kotlin.coroutines.jvm.internal.c {
    public l0 j;
    public /* synthetic */ Object k;
    public int l;
    public final /* synthetic */ l0 m;
    public Object n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public I(l0 l0Var, kotlin.coroutines.h hVar) {
        super(hVar);
        this.m = l0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.l |= Integer.MIN_VALUE;
        return this.m.emit(null, this);
    }
}
